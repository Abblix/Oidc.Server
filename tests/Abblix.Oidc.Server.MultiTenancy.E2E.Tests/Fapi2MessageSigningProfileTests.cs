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
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.ClientInformation;
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
/// A tenant holding its clients to FAPI 2.0 Message Signing refuses at the pushed authorization request endpoint
/// what sections 5.3.1 and 5.4.1 of that profile do not admit, lets through the same push with the one thing it
/// lacked put back, and answers at the authorization endpoint in a signed JWT.
/// </summary>
/// <remarks>
/// Nobody is signed in, so an accepted request is sent on to the login page, and one asking for no interaction is
/// answered with an error the response mode carries.
/// </remarks>
public sealed class Fapi2MessageSigningProfileTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string ClientId = "signing-client";
    private const string LoginPath = "/login";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri the client registers; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    /// <summary>
    /// The PKCE challenge of RFC 7636 appendix B.
    /// </summary>
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static readonly RsaJsonWebKey ClientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly TenantDefinition Tenant = new()
    {
        Id = "acme",
        Issuer = new Uri(Host + Acme),
        DefaultSecurityProfile = ClientSecurityProfile.Fapi2MessageSigning,
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
            options.ServiceTokens.AccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RefreshToken.Signing.Algorithm = SigningAlgorithms.PS256;            options.ServiceTokens.RegistrationAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;            options.ServiceTokens.InitialAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
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
        AllowedResponseTypes = [[ResponseTypes.Code]],
        RedirectUris = [new Uri(RedirectUri)],
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
        AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
    };

    /// <summary>
    /// The request a conformant client pushes: code with the jwt response mode, a PKCE S256 challenge, the openid
    /// scope and a nonce.
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
        [AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge,
        [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
    };

    /// <summary>
    /// <paramref name="parameters"/> signed PS256 into a request object with the client's key: by default addressed
    /// to the issuer, valid from now for five minutes and typed as section 5.3.1 has the server accept.
    /// </summary>
    private async Task<string> RequestObjectAsync(
        JsonObject parameters,
        bool addressedToTheIssuer = true,
        TimeSpan? notBeforeAgo = null,
        TimeSpan? lifetime = null)
    {
        var notBefore = TimeProvider.System.GetUtcNow() - (notBeforeAgo ?? TimeSpan.Zero);
        var token = new JsonWebToken
        {
            Header =
            {
                Algorithm = SigningAlgorithms.PS256,
                KeyId = ClientKey.KeyId,
                Type = JsonWebTokenTypes.RequestObject,
            },
            Payload =
            {
                Issuer = ClientId,
                IssuedAt = notBefore,
                NotBefore = notBefore,
                ExpiresAt = notBefore + (lifetime ?? TimeSpan.FromMinutes(5)),
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
    private async Task<string> ClientAssertionAsync()
    {
        var now = TimeProvider.System.GetUtcNow();
        return await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.PS256, KeyId = ClientKey.KeyId },
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
    /// Pushes the authorization request to the PAR endpoint, the client authenticating with a PS256 assertion:
    /// as the signed request object <paramref name="requestObject"/>, or as plain parameters where it is null.
    /// </summary>
    private async Task<HttpResponseMessage> PushAsync(string? requestObject, JsonObject? plainParameters = null)
    {
        var form = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = ClientId,
            [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
            [ClientRequest.Parameters.ClientAssertion] = await ClientAssertionAsync(),
        };

        if (requestObject is not null)
            form[AuthorizationRequest.Parameters.Request] = requestObject;

        foreach (var (name, value) in plainParameters ?? [])
            form[name] = value!.GetValue<string>();

        return await _http!.PostAsync(
            Acme + "/connect/par", new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Pushes <paramref name="parameters"/> in a conformant request object, requires the push to be accepted and
    /// follows the request_uri it was given to the authorization endpoint.
    /// </summary>
    private async Task<HttpResponseMessage> PushAndAuthorizeAsync(JsonObject parameters)
    {
        var pushed = await PushAsync(await RequestObjectAsync(parameters));
        Assert.Equal(HttpStatusCode.Created, pushed.StatusCode);

        var body = JsonNode.Parse(await pushed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = ClientId;
        query[AuthorizationRequest.Parameters.RequestUri] =
            body[PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>();

        return await _http!.GetAsync(Acme + "/connect/authorize?" + query, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The error in the JSON body of a refused push, or null when it carries none.
    /// </summary>
    private static async Task<string?> ErrorOf(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return body.HasValue() && JsonNode.Parse(body) is JsonObject json
            ? json[ErrorResponse.Parameters.Error]?.GetValue<string>()
            : null;
    }

    /// <summary>
    /// The conformant push is accepted and its request_uri sent on to the login page, which is what makes every
    /// refusal below the refusal of the one thing changed in it.
    /// </summary>
    [Fact]
    public async Task TheConformantPush_IsAccepted()
    {
        var response = await PushAndAuthorizeAsync(ConformantRequest());

        var location = Assert.IsType<Uri>(response.Headers.Location);
        var path = location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0];
        Assert.EndsWith(LoginPath, path, StringComparison.Ordinal);
    }

    /// <summary>
    /// Section 5.3.1: the server "shall support, require use of, and verify signed request objects according to JAR
    /// [RFC9101] at the PAR endpoint [RFC9126]", so the same parameters pushed in the clear are refused.
    /// </summary>
    [Fact]
    public async Task APushInPlainParameters_IsRefused()
    {
        var response = await PushAsync(requestObject: null, ConformantRequest());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, await ErrorOf(response));
    }

    /// <summary>
    /// Section 5.3.1: the server "shall require the aud claim in the request object to be, or to be an array
    /// containing, the authorization server's issuer identifier URL".
    /// </summary>
    [Fact]
    public async Task ARequestObjectWithoutAudience_IsRefused()
    {
        var response = await PushAsync(await RequestObjectAsync(ConformantRequest(), addressedToTheIssuer: false));

        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorOf(response));
    }

    /// <summary>
    /// Section 5.3.1: the server "shall require the request object to contain an nbf claim that is no longer than 60
    /// minutes in the past". An object valid for five minutes from an nbf 61 minutes ago is refused; one from an nbf
    /// 59 minutes ago, still valid, is accepted.
    /// </summary>
    [Theory]
    [InlineData(61, HttpStatusCode.BadRequest)]
    [InlineData(59, HttpStatusCode.Created)]
    public async Task TheRequestObjectNotBefore_IsWithinAnHour(int minutesAgo, HttpStatusCode expected)
    {
        var requestObject = await RequestObjectAsync(
            ConformantRequest(),
            notBeforeAgo: TimeSpan.FromMinutes(minutesAgo),
            lifetime: TimeSpan.FromMinutes(minutesAgo + 1));

        var response = await PushAsync(requestObject);

        Assert.Equal(expected, response.StatusCode);
    }

    /// <summary>
    /// Section 5.3.1: the server "shall require the request object to contain an exp claim that has a lifetime of no
    /// longer than 60 minutes after the nbf claim".
    /// </summary>
    [Theory]
    [InlineData(61, HttpStatusCode.BadRequest)]
    [InlineData(60, HttpStatusCode.Created)]
    public async Task TheRequestObjectLifetime_IsAnHourAtMost(int minutes, HttpStatusCode expected)
    {
        var response = await PushAsync(
            await RequestObjectAsync(ConformantRequest(), lifetime: TimeSpan.FromMinutes(minutes)));

        Assert.Equal(expected, response.StatusCode);
    }

    /// <summary>
    /// Section 5.4.1: the server "shall support, require use of, and issue signed authorization responses via JWT
    /// Secured Authorization Response Mode for OAuth 2.0 [JARM]". A plain response mode, or none, is refused at the
    /// push; every JARM mode is accepted.
    /// </summary>
    [Theory]
    [InlineData(ResponseModes.Query, ErrorCodes.UnsupportedResponseType)]
    [InlineData(null, ErrorCodes.UnsupportedResponseType)]
    [InlineData(ResponseModes.Jwt, null)]
    [InlineData(ResponseModes.QueryJwt, null)]
    [InlineData(ResponseModes.FormPostJwt, null)]
    public async Task OnlyAJarmResponseMode_IsAccepted(string? responseMode, string? expectedError)
    {
        var request = ConformantRequest();
        request[AuthorizationRequest.Parameters.ResponseMode] = responseMode;
        if (responseMode is null)
            request.Remove(AuthorizationRequest.Parameters.ResponseMode);

        var response = await PushAsync(await RequestObjectAsync(request));

        Assert.Equal(expectedError, await ErrorOf(response));
    }

    /// <summary>
    /// Section 5.3.3 introduces the response_modes client metadata, "the list of response modes that the client may
    /// use". A registration listing only a plain mode could send no request section 5.4.1 admits and is refused; one
    /// listing a JARM mode is registered and the list is returned as sent.
    /// </summary>
    [Theory]
    [InlineData(ResponseModes.Query, HttpStatusCode.BadRequest)]
    [InlineData(ResponseModes.QueryJwt, HttpStatusCode.Created)]
    public async Task ARegistrationsResponseModes_IncludeAJarmMode(string responseMode, HttpStatusCode expected)
    {
        var response = await _http!.PostAsync(
            Acme + "/connect/register",
            new StringContent(
                new JsonObject
                {
                    [RegistrationParameters.RedirectUris] = new JsonArray { RedirectUri },
                    [RegistrationParameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
                    [RegistrationParameters.ResponseModes] = new JsonArray { responseMode },
                    [RegistrationParameters.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
                    [RegistrationParameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt,
                    [RegistrationParameters.Jwks] = JsonSerializer.SerializeToNode(
                        new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)])),
                }.ToJsonString(),
                Encoding.UTF8,
                "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(expected, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        if (expected == HttpStatusCode.BadRequest)
        {
            Assert.Equal(ErrorCodes.InvalidClientMetadata, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
            return;
        }

        Assert.Equal(
            [responseMode],
            body[RegistrationParameters.ResponseModes]!.AsArray().Select(mode => mode!.GetValue<string>()));
    }

    /// <summary>
    /// The response itself is a JWT signed PS256 (FAPI 2.0 Security Profile section 5.4.1) in the one response
    /// parameter JARM section 2.3.1 names, with the issuer inside it and not beside it: the note under section 5.4.1
    /// has the server "only include the iss authorization response parameter defined by [RFC9207] inside the JWT".
    /// An error is answered the same way, as JARM section 2.4 has it.
    /// </summary>
    [Fact]
    public async Task TheResponse_IsASignedJwtCarryingTheIssuer()
    {
        var request = ConformantRequest();
        request[AuthorizationRequest.Parameters.Prompt] = Prompts.None;

        var response = await PushAndAuthorizeAsync(request);

        var location = Assert.IsType<Uri>(response.Headers.Location);
        Assert.StartsWith(RedirectUri, location.OriginalString, StringComparison.Ordinal);
        var parameters = HttpUtility.ParseQueryString(location.Query);
        Assert.Equal([ResponseParameters.Response], parameters.AllKeys);

        var parts = parameters[ResponseParameters.Response]!.Split('.');
        var header = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0])))!;
        var payload = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1])))!;
        Assert.Equal(SigningAlgorithms.PS256, header[JwtClaimTypes.Algorithm]!.GetValue<string>());
        Assert.Equal(Host + Acme, payload[JwtClaimTypes.Issuer]!.GetValue<string>());
        Assert.Equal(ErrorCodes.LoginRequired, payload[ResponseParameters.Error]!.GetValue<string>());
    }
}
