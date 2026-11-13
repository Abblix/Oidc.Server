// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

using RegistrationParameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant holding its clients to FAPI 1.0 Advanced refuses at the authorization endpoint what that profile does
/// not admit, and lets through the same request with the one thing it lacked put back.
/// </summary>
/// <remarks>
/// Every request reaches the endpoint unauthenticated, so one the endpoint accepts is sent on to the login page;
/// that redirect is what tells an accepted request from a refused one.
/// </remarks>
public sealed class Fapi1AdvancedProfileTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string ClientId = "fapi1-client";
    private const string LoginPath = "/login";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri the client registers; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private static readonly RsaJsonWebKey ClientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly TenantDefinition Tenant = new()
    {
        Id = "acme",
        Issuer = new Uri(Host + Acme),
        DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced,
        Clients = [Client()],
        LoginUri = new Uri(LoginPath, UriKind.Relative),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private WebApplication? _app;
    private HttpClient? _http;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddDynamicClientRegistration();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.RegisterClient;
            options.RequireInitialAccessToken = false;
        });
        builder.Services.Configure<OidcOptions>(options => options.Tenants.Add(Tenant));

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    private static ClientInfo Client() => new(ClientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
        AllowedGrantTypes = [GrantTypes.AuthorizationCode],
        AllowedResponseTypes = [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
        RedirectUris = [new Uri(RedirectUri)],
        // FAPI 1.0 Part 2 asks PKCE only of a pushed request, and these requests go by value
        PkceRequired = false,
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
        AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
    };

    /// <summary>
    /// The request a conformant client sends: code with the JWT response mode, the openid scope and a nonce, in a
    /// request object addressed to the issuer, signed PS256, living five minutes.
    /// </summary>
    private static JsonObject ConformantRequest() => new()
    {
        [AuthorizationRequest.Parameters.ClientId] = ClientId,
        [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
        [AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.Jwt,
        [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
        [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
        [AuthorizationRequest.Parameters.State] = "state-1",
        [AuthorizationRequest.Parameters.Nonce] = "nonce-1",
    };

    /// <summary>
    /// Signs <paramref name="parameters"/> into a request object and sends it to the authorization endpoint by
    /// value, with the client_id and response_type duplicates RFC 9101 section 5 and OpenID Connect Core section 6.1
    /// expect outside it.
    /// </summary>
    private async Task<HttpResponseMessage> AuthorizeAsync(
        JsonObject parameters,
        string algorithm = SigningAlgorithms.PS256,
        bool addressedToTheIssuer = true,
        string clientId = ClientId,
        string scope = Scopes.OpenId)
    {
        var requestObject = await RequestObjectAsync(parameters, algorithm, addressedToTheIssuer, clientId);

        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = clientId;
        query[AuthorizationRequest.Parameters.ResponseType] =
            parameters[AuthorizationRequest.Parameters.ResponseType]!.GetValue<string>();
        query[AuthorizationRequest.Parameters.Scope] = scope;
        query[AuthorizationRequest.Parameters.Request] = requestObject;

        return await _http!.GetAsync(Acme + "/connect/authorize?" + query, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// <paramref name="parameters"/> signed into a request object with the client's key, living five minutes.
    /// </summary>
    private async Task<string> RequestObjectAsync(
        JsonObject parameters,
        string algorithm = SigningAlgorithms.PS256,
        bool addressedToTheIssuer = true,
        string clientId = ClientId)
    {
        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = algorithm, KeyId = ClientKey.KeyId },
            Payload =
            {
                Issuer = clientId,
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
        if (addressedToTheIssuer)
            token.Payload.Audiences = [Host + Acme];

        foreach (var (name, value) in parameters)
            token.Payload.Json[name] = value?.DeepClone();

        return await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, ClientKey);
    }

    /// <summary>
    /// A private_key_jwt client authentication assertion (OpenID Connect Core section 9) addressed to the issuer.
    /// </summary>
    private async Task<string> ClientAssertionAsync(string algorithm = SigningAlgorithms.PS256)
    {
        var now = TimeProvider.System.GetUtcNow();
        return await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = algorithm, KeyId = ClientKey.KeyId },
                Payload =
                {
                    Issuer = ClientId,
                    Subject = ClientId,
                    Audiences = [Host + Acme],
                    JwtId = Guid.NewGuid().ToString("N"),
                    IssuedAt = now,
                    ExpiresAt = now.AddMinutes(1),
                },
            },
            ClientKey);
    }

    /// <summary>
    /// Pushes <paramref name="parameters"/> as a signed request object to the pushed authorization request endpoint,
    /// the client authenticating with a PS256 assertion.
    /// </summary>
    private async Task<HttpResponseMessage> PushAsync(JsonObject parameters)
        => await _http!.PostAsync(
            Acme + "/connect/par",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
                [ClientRequest.Parameters.ClientAssertion] = await ClientAssertionAsync(),
                [AuthorizationRequest.Parameters.Request] = await RequestObjectAsync(parameters),
            }),
            TestContext.Current.CancellationToken);

    /// <summary>
    /// The error the response carries, wherever the endpoint put it: in the redirect's query or fragment, inside
    /// the JWT a JWT response mode wraps it in, or in the body of a response sent to the browser; null when it
    /// carries none.
    /// </summary>
    private static async Task<string?> ErrorOf(HttpResponseMessage response)
    {
        if (response.Headers.Location is { } location)
        {
            var parameters = HttpUtility.ParseQueryString(
                location.IsAbsoluteUri ? location.Query.TrimStart('?') + "&" + location.Fragment.TrimStart('#') : "");

            if (parameters[ResponseParameters.Error] is { } error)
                return error;

            if (parameters[ResponseParameters.Response] is { } wrapped)
            {
                var payload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(wrapped.Split('.')[1]));
                return JsonNode.Parse(payload)![ResponseParameters.Error]?.GetValue<string>();
            }

            return null;
        }

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return body.HasValue() && JsonNode.Parse(body) is JsonObject json
            ? json[ErrorResponse.Parameters.Error]?.GetValue<string>()
            : null;
    }

    /// <summary>
    /// What an accepted request ends in here: a redirect to the login page, since nobody is signed in.
    /// </summary>
    private static async Task AssertSentToLogin(HttpResponseMessage response)
    {
        var location = Assert.IsType<Uri>(response.Headers.Location);
        var path = location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0];
        Assert.True(path.EndsWith(LoginPath, StringComparison.Ordinal), $"{response.StatusCode}, error {await ErrorOf(response)}");
    }

    /// <summary>
    /// The conformant request is accepted, which is what makes every refusal below the refusal of the one thing
    /// changed in it.
    /// </summary>
    [Fact]
    public async Task TheConformantRequest_IsAccepted()
    {
        await AssertSentToLogin(await AuthorizeAsync(ConformantRequest()));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2 requires "the response_type value code id_token, or the response_type value
    /// code in conjunction with the response_mode value jwt", so plain code, whose response nothing signs, is
    /// refused.
    /// </summary>
    [Fact]
    public async Task PlainCode_WithoutTheJwtResponseMode_IsRefused()
    {
        var request = ConformantRequest();
        request.Remove(AuthorizationRequest.Parameters.ResponseMode);

        Assert.Equal(ErrorCodes.UnsupportedResponseType, await ErrorOf(await AuthorizeAsync(request)));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2 requires "the aud claim in the request object to be, or to be an array
    /// containing, the OP's Issuer Identifier URL", so an object naming no audience is refused.
    /// </summary>
    [Fact]
    public async Task ARequestObjectWithoutAudience_IsRefused()
    {
        Assert.Equal(
            ErrorCodes.InvalidRequestObject,
            await ErrorOf(await AuthorizeAsync(ConformantRequest(), addressedToTheIssuer: false)));
    }

    /// <summary>
    /// FAPI 1.0 Part 1 section 5.2.2.2, taken in by Part 2 section 5.2.2: "If the client requests the openid scope,
    /// the authorization server shall require the nonce parameter". Code with the JWT response mode returns no ID
    /// token from the authorization endpoint, so OpenID Connect Core alone would let this request through.
    /// </summary>
    [Fact]
    public async Task OpenIdScopeWithoutNonce_IsRefused()
    {
        var request = ConformantRequest();
        request.Remove(AuthorizationRequest.Parameters.Nonce);

        Assert.Equal(ErrorCodes.InvalidRequest, await ErrorOf(await AuthorizeAsync(request)));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6: "For JWS, both clients and authorization servers shall use PS256 or ES256
    /// algorithms", so a request object signed RS256 is refused although the client's key verifies it.
    /// </summary>
    [Fact]
    public async Task ARequestObjectSignedRs256_IsRefused()
    {
        Assert.Equal(
            ErrorCodes.InvalidRequestObject,
            await ErrorOf(await AuthorizeAsync(ConformantRequest(), SigningAlgorithms.RS256)));
    }

    /// <summary>
    /// The same holds for the client authentication assertion at the token endpoint: one signed RS256 does not
    /// authenticate the client, while one signed PS256 does, and the request goes on to be refused for the code it
    /// carries, which no authorization issued.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, ErrorCodes.InvalidClient)]
    [InlineData(SigningAlgorithms.PS256, ErrorCodes.InvalidGrant)]
    public async Task TheClientAssertion_IsJudgedByItsAlgorithm(string algorithm, string expectedError)
    {
        var assertion = await ClientAssertionAsync(algorithm);

        using var request = new HttpRequestMessage(HttpMethod.Post, Acme + "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = "no-such-code",
                [TokenRequest.Parameters.RedirectUri] = RedirectUri,
                [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
                [ClientRequest.Parameters.ClientAssertion] = assertion,
            }),
        };
        // The profile requires a sender-constrained token, and the proof is checked before the client is
        request.Headers.Add(DPoPHeader, await DPoPProofAsync(HttpMethod.Post, new Uri(Host + Acme + "/connect/token")));

        var response = await _http!.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(expectedError, await ErrorOf(response));
    }

    /// <summary>
    /// The request header RFC 9449 section 4.1 carries a DPoP proof in.
    /// </summary>
    private const string DPoPHeader = "DPoP";

    /// <summary>
    /// A DPoP proof (RFC 9449 section 4.2) for one request, signed ES256 with a fresh key carried in its header.
    /// </summary>
    private async Task<string> DPoPProofAsync(HttpMethod method, Uri target)
    {
        var key = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
        var proof = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.ES256, Type = JsonWebTokenTypes.DPoPProof },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                IssuedAt = TimeProvider.System.GetUtcNow(),
            },
        };
        proof.Header.Json[JwtClaimTypes.JsonWebKeyHeader] = JsonSerializer.SerializeToNode(key.Sanitize(includePrivateKeys: false));
        proof.Payload.Json[IanaClaimTypes.Htm] = method.Method;
        proof.Payload.Json[IanaClaimTypes.Htu] = target.AbsoluteUri;

        return await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(proof, key);
    }

    /// <summary>
    /// A client put into the store after startup, at the RS256 defaults no startup check saw, is refused at the
    /// authorization endpoint before the server signs anything for it: FAPI 1.0 Part 2 section 8.6 names PS256 and
    /// ES256 for what the server signs.
    /// </summary>
    [Fact]
    public async Task AStoredClientAtTheRs256Defaults_IsRefusedAtTheAuthorizationEndpoint()
    {
        const string storedClientId = "stored-at-the-defaults";
        var stored = Client();
        Assert.True(await _app!.Services.GetRequiredService<IClientInfoManager>().TryAddClientAsync(
            Tenant,
            new RegisteredClient(
                new ClientInfo(storedClientId)
                {
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
                    Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
                    AllowedResponseTypes = stored.AllowedResponseTypes,
                    RedirectUris = stored.RedirectUris,
                    PkceRequired = false,
                },
                "registration-access-token-id")));
        var request = ConformantRequest();
        request[AuthorizationRequest.Parameters.ClientId] = storedClientId;

        Assert.Equal(ErrorCodes.UnauthorizedClient, await ErrorOf(await AuthorizeAsync(request, clientId: storedClientId)));
    }

    /// <summary>
    /// A client registering at this tenant without naming its signature algorithms is given one the tenant's RSA key
    /// produces and FAPI 1.0 Part 2 section 8.6 admits, and the registration response says which.
    /// </summary>
    [Fact]
    public async Task ARegistrationNamingNoAlgorithm_IsGivenOneTheTenantsKeyProduces()
    {
        var response = await _http!.PostAsync(
            Acme + "/connect/register",
            new StringContent(
                new JsonObject
                {
                    [RegistrationParameters.RedirectUris] = new JsonArray { RedirectUri },
                    [RegistrationParameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
                    [RegistrationParameters.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
                    [RegistrationParameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt,
                    [RegistrationParameters.Jwks] = JsonSerializer.SerializeToNode(
                        new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)])),
                }.ToJsonString(),
                Encoding.UTF8,
                "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var registered = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(
            SigningAlgorithms.PS256,
            registered[RegistrationParameters.IdTokenSignedResponseAlg]!.GetValue<string>());
        Assert.Equal(
            SigningAlgorithms.PS256,
            registered[RegistrationParameters.AuthorizationSignedResponseAlg]!.GetValue<string>());
    }

    /// <summary>
    /// A tenant holding only a P-256 key and declaring a client configured for PS256 does not start: no key of it
    /// produces the algorithm, and the first ID token would otherwise fail as a server error. The same tenant with the
    /// client configured for ES256 starts, which is what shows the refusal is about the algorithm.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.PS256, false)]
    [InlineData(SigningAlgorithms.ES256, true)]
    public async Task ATenantWhoseKeysCannotSignForItsClient_DoesNotStart(string algorithm, bool starts)
    {
        var client = Client();
        client.IdentityTokenSignedResponseAlgorithm = algorithm;
        client.AuthorizationSignedResponseAlgorithm = algorithm;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(_ => { });
        builder.Services.Configure<OidcOptions>(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(Host + Acme),
            DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced,
            Clients = [client],
            SigningKeys = [JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256)],
        }));
        await using var app = builder.Build();

        var start = await Record.ExceptionAsync(() =>
        {
            app.UseMultiTenancy();
            app.UseCors();
            app.UseAuthorization();
            app.MapOidcEndpoints();
            return app.StartAsync(TestContext.Current.CancellationToken);
        });

        if (starts)
            Assert.Null(start);
        else
            Assert.IsType<Microsoft.Extensions.Options.OptionsValidationException>(start);
    }

    /// <summary>
    /// FAPI 1.0 Part 1 section 5.2.2.3, taken in by Part 2 section 5.2.2: "If the client does not requests the openid
    /// scope, the authorization server shall require the state parameter". A request naming no openid scope is
    /// refused without state and accepted with it.
    /// </summary>
    [Theory]
    [InlineData(null, ErrorCodes.InvalidRequest)]
    [InlineData("state-1", null)]
    public async Task WithoutTheOpenIdScope_StateIsRequired(string? state, string? expectedError)
    {
        var request = ConformantRequest();
        request[AuthorizationRequest.Parameters.Scope] = Scopes.Profile;
        request.Remove(AuthorizationRequest.Parameters.Nonce);
        request.Remove(AuthorizationRequest.Parameters.State);
        if (state != null)
            request[AuthorizationRequest.Parameters.State] = state;

        var response = await AuthorizeAsync(request, scope: Scopes.Profile);

        if (expectedError == null)
            await AssertSentToLogin(response);
        else
            Assert.Equal(expectedError, await ErrorOf(response));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2: the server "shall require PAR requests, if supported, to use PKCE (RFC7636) with
    /// S256 as the code challenge method". A pushed request without a code challenge is refused; the same request with
    /// an S256 challenge is accepted.
    /// </summary>
    [Theory]
    [InlineData(false, HttpStatusCode.BadRequest)]
    [InlineData(true, HttpStatusCode.Created)]
    public async Task APushedRequest_CarriesAnS256CodeChallenge(bool withChallenge, HttpStatusCode expected)
    {
        var request = ConformantRequest();
        if (withChallenge)
        {
            request[AuthorizationRequest.Parameters.CodeChallenge] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
            request[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;
        }

        var response = await PushAsync(request);

        Assert.Equal(expected, response.StatusCode);
        if (!withChallenge)
            Assert.Equal(ErrorCodes.InvalidRequest, await ErrorOf(response));
    }

    /// <summary>
    /// FAPI 1.0 Part 1 section 5.2.2: "shall require redirect URIs to use the https scheme". A tenant declaring a FAPI
    /// 1.0 Advanced client with an http loopback redirect URI does not start; the same client with an https one does.
    /// </summary>
    [Theory]
    [InlineData("http://127.0.0.1:8080/cb", false)]
    [InlineData("https://client.example.com/cb", true)]
    public async Task ATenantDeclaringAnHttpRedirectUri_DoesNotStart(string redirectUri, bool starts)
    {
        var client = Client();
        client.RedirectUris = [new Uri(redirectUri)];
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(_ => { });
        builder.Services.Configure<OidcOptions>(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(Host + Acme),
            DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced,
            Clients = [client],
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));
        await using var app = builder.Build();

        var start = await Record.ExceptionAsync(() =>
        {
            app.UseMultiTenancy();
            app.UseCors();
            app.UseAuthorization();
            app.MapOidcEndpoints();
            return app.StartAsync(TestContext.Current.CancellationToken);
        });

        if (starts)
            Assert.Null(start);
        else
            Assert.IsType<Microsoft.Extensions.Options.OptionsValidationException>(start);
    }
}
