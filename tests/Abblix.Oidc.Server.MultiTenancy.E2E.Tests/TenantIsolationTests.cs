// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using ValidUserCode = Abblix.Oidc.Server.Features.DeviceAuthorization.ValidUserCode;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants served by one running server, each with a client of the same id and the same secret, so nothing
/// but the tenant tells their requests apart: what one tenant issued must not be honoured by the other.
/// </summary>
public sealed class TenantIsolationTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "shared-client-id";
    private const string AcmeOnlyClientId = "acme-only-client-id";
    private const string PairwiseClientId = "pairwise-client-id";
    private const string ClientSecret = "shared-client-secret";
    private const string AcmeScope = "acme:read";
    private const string PushPath = "/connect/par";
    private const string TokenPath = "/connect/token";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string AcmeResource = "https://api.acme.example";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri both tenants' clients register; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private WebApplication? _app;
    private HttpClient? _http;

    private HttpClient Http => _http!;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        // What a host supplies to the server: a cache for its storage, a cookie scheme for the signed-in user.
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();

        // Grant features before AddOidcServices, which composes the grant handlers.
        builder.Services.AddDeviceAuthorization();
        builder.Services.AddCheckSession();
        builder.Services.AddOidcServices(options =>
        {
            options.DeviceAuthorization = new DeviceAuthorizationOptions
            {
                // Relative, so each tenant's users are sent to the page under that tenant's path
                VerificationUri = new Uri("device", UriKind.Relative),
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
            };
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.CheckSession;
        });
        builder.Services.AddMultiTenancy(options =>
        {
            // Both tenants register a client under the same id; only acme registers the second one
            options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = Host + Acme,
                Clients = [Client(ClientId), Client(AcmeOnlyClientId), PairwiseClient()],
                PairwiseSubject = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) },
                Scopes = [new ScopeDefinition(AcmeScope)],
                Resources = [new ResourceDefinition(new Uri(AcmeResource), new ScopeDefinition(AcmeScope))],
                DefaultResourceIndicator = new Uri(AcmeResource),
                LoginUri = new Uri("/login", UriKind.Relative),
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
            });
            options.Tenants.Add(new TenantDefinition
            {
                Id = "globex",
                Issuer = Host + Globex,
                Clients = [Client(ClientId), PairwiseClient()],
                LoginUri = new Uri("/sign-in", UriKind.Relative),
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
                PairwiseSubject = new PairwiseSubjectSettings
                {
                    Salt = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()),
                },
            });
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();

        // The host's page the user enters the code on; the tenant comes from the path it is reached under
        _app.MapPost("/device", async (HttpContext context, IUserCodeVerificationService verification) =>
        {
            var userCode = (await context.Request.ReadFormAsync())[DeviceAuthorizationResponse.Parameters.UserCode]
                .ToString();

            if (await verification.VerifyAsync(userCode) is not ValidUserCode valid)
                return Results.BadRequest();

            var grant = new AuthorizedGrant(
                new AuthSession(
                    "alice",
                    "session-1",
                    context.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow(),
                    "local"),
                new AuthorizationContext(valid.ClientId, valid.Scope, null));

            return await verification.ApproveAsync(userCode, grant) ? Results.Ok() : Results.Conflict();
        });

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

    private static ClientInfo Client(string clientId) => new(clientId)
    {
        ClientSecrets = [new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) }],
        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
        AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.DeviceAuthorization],
        RedirectUris = [new Uri(RedirectUri)],
        PkceRequired = true,
    };

    private static ClientInfo PairwiseClient()
    {
        var client = Client(PairwiseClientId);
        client.SubjectType = SubjectTypes.Pairwise;
        return client;
    }

    private Task<HttpResponseMessage> PostAsync(string tenant, string path, Dictionary<string, string> form)
        => PostAsync(tenant, path, ClientId, form);

    private Task<HttpResponseMessage> PostAsync(
        string tenant,
        string path,
        string clientId,
        Dictionary<string, string> form)
    {
        form[ClientRequest.Parameters.ClientId] = clientId;
        form[ClientRequest.Parameters.ClientSecret] = ClientSecret;
        return Http.PostAsync(tenant + path, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);
    }

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    /// <summary>
    /// A client one tenant registers authenticates there, and the other tenant, which never registered it, refuses
    /// it as unknown.
    /// </summary>
    [Fact]
    public async Task AClientOfOneTenant_IsUnknownToTheOther()
    {
        Dictionary<string, string> Push() => new()
        {
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = "S256",
        };

        var atAcme = await PostAsync(Acme, PushPath, AcmeOnlyClientId, Push());
        Assert.Equal(HttpStatusCode.Created, atAcme.StatusCode);

        var atGlobex = await PostAsync(Globex, PushPath, AcmeOnlyClientId, Push());
        Assert.Equal(HttpStatusCode.Unauthorized, atGlobex.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClient, (await ReadJsonAsync(atGlobex))[ResponseParameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// A scope and a resource one tenant defines are granted there, and the other tenant, which never defined them,
    /// refuses a request naming either.
    /// </summary>
    [Fact]
    public async Task AScopeAndAResourceOfOneTenant_AreUnknownToTheOther()
    {
        Dictionary<string, string> Push(string scope, string? resource = null)
        {
            var form = new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = scope,
                [AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge,
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = "S256",
            };
            if (resource is not null)
                form[AuthorizationRequest.Parameters.Resource] = resource;
            return form;
        }

        Assert.Equal(HttpStatusCode.Created, (await PostAsync(Acme, PushPath, Push("openid " + AcmeScope))).StatusCode);
        var scopeAtGlobex = await PostAsync(Globex, PushPath, Push("openid " + AcmeScope));
        Assert.Equal(ErrorCodes.InvalidScope, (await ReadJsonAsync(scopeAtGlobex))[ResponseParameters.Error]?.GetValue<string>());

        Assert.Equal(
            HttpStatusCode.Created,
            (await PostAsync(Acme, PushPath, Push("openid " + AcmeScope, AcmeResource))).StatusCode);
        var resourceAtGlobex = await PostAsync(Globex, PushPath, Push(Scopes.OpenId, AcmeResource));
        Assert.Equal(ErrorCodes.InvalidTarget, (await ReadJsonAsync(resourceAtGlobex))[ResponseParameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// The same user signing in to the same pairwise client at two tenants gets a different pseudonym at each, since
    /// each tenant seals them with its own key.
    /// </summary>
    [Fact]
    public async Task APairwiseSubject_DiffersFromTenantToTenant()
    {
        var atAcme = await SubjectOfADeviceFlowAsync(Acme);
        var atGlobex = await SubjectOfADeviceFlowAsync(Globex);

        Assert.NotEqual("alice", atAcme);
        Assert.NotEqual("alice", atGlobex);
        Assert.NotEqual(atAcme, atGlobex);
    }

    /// <summary>
    /// A party trusting one tenant's published keys verifies that tenant's tokens and no other's: each tenant signs
    /// with keys of its own.
    /// </summary>
    [Fact]
    public async Task ATokenOfOneTenant_IsVerifiedByThatTenantsKeysAlone()
    {
        var token = await AccessTokenOfADeviceFlowAsync(Acme);

        Assert.True(SignedByOneOf(token, await PublishedKeysAsync(Acme)));
        Assert.False(SignedByOneOf(token, await PublishedKeysAsync(Globex)));
    }

    /// <summary>
    /// The keys <paramref name="tenant"/> publishes at the JWKS address its discovery document names.
    /// </summary>
    private async Task<RsaJsonWebKey[]> PublishedKeysAsync(string tenant)
    {
        var configuration = JsonNode.Parse(await Http.GetStringAsync(
            tenant + "/.well-known/openid-configuration", TestContext.Current.CancellationToken))!;
        var jwks = await Http.GetStringAsync(
            configuration[ConfigurationResponse.Parameters.JwksUri]!.GetValue<string>(),
            TestContext.Current.CancellationToken);

        var keys = JsonSerializer.Deserialize<JsonWebKeySet>(jwks)!.Keys.OfType<RsaJsonWebKey>().ToArray();
        Assert.NotEmpty(keys);
        return keys;
    }

    /// <summary>
    /// Whether one of <paramref name="keys"/> verifies the RS256 signature of <paramref name="token"/>, as a party
    /// holding only those keys would check it.
    /// </summary>
    private static bool SignedByOneOf(string token, RsaJsonWebKey[] keys)
    {
        var parts = token.Split('.');
        var header = JsonNode.Parse(Base64Url.DecodeFromChars(parts[0]))!;
        Assert.Equal(SigningAlgorithms.RS256, header[JwtClaimTypes.Algorithm]!.GetValue<string>());

        var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64Url.DecodeFromChars(parts[2]);
        return keys.Any(key =>
        {
            using var rsa = RSA.Create(new RSAParameters { Modulus = key.Modulus, Exponent = key.Exponent });
            return rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        });
    }

    /// <summary>
    /// The subject of the access token the pairwise client gets at <paramref name="tenant"/> once the user the
    /// verification page signs in approves its device.
    /// </summary>
    private async Task<string> SubjectOfADeviceFlowAsync(string tenant)
    {
        var accessToken = await AccessTokenOfADeviceFlowAsync(tenant);
        var payload = JsonNode.Parse(Base64Url.DecodeFromChars(accessToken.Split('.')[1]))!;
        return payload[IanaClaimTypes.Sub]!.GetValue<string>();
    }

    /// <summary>
    /// The access token the pairwise client gets at <paramref name="tenant"/> once the user the verification page
    /// signs in approves its device.
    /// </summary>
    private async Task<string> AccessTokenOfADeviceFlowAsync(string tenant)
    {
        var authorization = await ReadJsonAsync(await PostAsync(tenant, "/connect/deviceauthorization", PairwiseClientId,
            new Dictionary<string, string> { [DeviceAuthorizationRequest.Parameters.Scope] = Scopes.OpenId }));

        var approved = await Http.PostAsync(
            authorization[DeviceAuthorizationResponse.Parameters.VerificationUri]!.GetValue<string>(),
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [DeviceAuthorizationResponse.Parameters.UserCode] =
                    authorization[DeviceAuthorizationResponse.Parameters.UserCode]!.GetValue<string>(),
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);

        var tokens = await ReadJsonAsync(await PostAsync(tenant, TokenPath, PairwiseClientId,
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.DeviceAuthorization,
                [TokenRequest.Parameters.DeviceCode] =
                    authorization[DeviceAuthorizationResponse.Parameters.DeviceCode]!.GetValue<string>(),
            }));
        return tokens[ResponseParameters.AccessToken]!.GetValue<string>();
    }

    /// <summary>
    /// Each tenant's session cookie carries a name of its own, so two tenants on one host, whose cookies share the
    /// host and the path, do not overwrite each other's, and each tenant's check-session page reads its own.
    /// </summary>
    [Fact]
    public async Task EachTenant_ReadsASessionCookieOfItsOwn()
    {
        var atAcme = await Http.GetStringAsync(Acme + "/connect/checksession", TestContext.Current.CancellationToken);
        var atGlobex = await Http.GetStringAsync(Globex + "/connect/checksession", TestContext.Current.CancellationToken);

        Assert.Contains("\"Abblix.SessionId.acme\"", atAcme, StringComparison.Ordinal);
        Assert.Contains("\"Abblix.SessionId.globex\"", atGlobex, StringComparison.Ordinal);
    }

    /// <summary>
    /// A pushed authorization request registered with one tenant is not found by the other: its request_uri
    /// names a request the other tenant never received.
    /// </summary>
    [Fact]
    public async Task APushedRequestOfOneTenant_IsUnknownToTheOther()
    {
        var pushed = await PostAsync(Acme, PushPath, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = "S256",
        });
        Assert.Equal(HttpStatusCode.Created, pushed.StatusCode);
        var requestUri = (await ReadJsonAsync(pushed))[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        var query = $"/connect/authorize?client_id={ClientId}&request_uri={Uri.EscapeDataString(requestUri)}";

        var atGlobex = await Http.GetAsync(Globex + query, TestContext.Current.CancellationToken);
        var globexAnswer = atGlobex.Headers.Location?.ToString()
                           ?? await atGlobex.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains(ErrorCodes.InvalidRequestUri, globexAnswer, StringComparison.Ordinal);

        // 303 rather than 302: the authorization endpoint also accepts POST, whose body may carry the user's
        // credentials, and 303 makes the user agent follow with a GET that never re-sends that body. RFC 9700
        // section 4.12: such a server "MUST NOT use the HTTP 307" and "SHOULD use HTTP status code 303 (See Other)".
        var atAcme = await Http.GetAsync(Acme + query, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.SeeOther, atAcme.StatusCode);
        Assert.StartsWith(Host + Acme + "/login", atAcme.Headers.Location?.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// Each tenant sends its users to the sign-in page it declares, under its own path.
    /// </summary>
    [Fact]
    public async Task EachTenant_SendsItsUsersToItsOwnSignInPage()
    {
        var pushed = await PostAsync(Globex, PushPath, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = "S256",
        });
        var requestUri = (await ReadJsonAsync(pushed))[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        var atGlobex = await Http.GetAsync(
            Globex + $"/connect/authorize?client_id={ClientId}&request_uri={Uri.EscapeDataString(requestUri)}",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.SeeOther, atGlobex.StatusCode);
        Assert.StartsWith(Host + Globex + "/sign-in", atGlobex.Headers.Location?.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A device code one tenant issued is unknown at the other tenant's token endpoint, and still pending at its own.
    /// </summary>
    [Fact]
    public async Task ADeviceCodeOfOneTenant_IsUnknownToTheOther()
    {
        var authorization = await PostAsync(Acme, "/connect/deviceauthorization", new Dictionary<string, string>
        {
            [DeviceAuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
        });
        Assert.Equal(HttpStatusCode.OK, authorization.StatusCode);
        var deviceCode = (await ReadJsonAsync(authorization))[DeviceAuthorizationResponse.Parameters.DeviceCode]!.GetValue<string>();

        var poll = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.DeviceAuthorization,
            [TokenRequest.Parameters.DeviceCode] = deviceCode,
        };

        var atGlobex = await PostAsync(Globex, TokenPath, new Dictionary<string, string>(poll));
        Assert.Equal(ErrorCodes.InvalidGrant, (await ReadJsonAsync(atGlobex))[ResponseParameters.Error]?.GetValue<string>());

        var atAcme = await PostAsync(Acme, TokenPath, new Dictionary<string, string>(poll));
        Assert.Equal(ErrorCodes.AuthorizationPending, (await ReadJsonAsync(atAcme))[ResponseParameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// A device flow completes: the device is sent to its own tenant's verification page, the user code entered
    /// there is approved, and the device then gets its tokens, issued for the resource that tenant names as its
    /// default. The other tenant's page does not know the code.
    /// </summary>
    [Fact]
    public async Task ADeviceFlow_CompletesOnItsOwnTenantsVerificationPage()
    {
        var authorization = await ReadJsonAsync(await PostAsync(Acme, "/connect/deviceauthorization",
            new Dictionary<string, string> { [DeviceAuthorizationRequest.Parameters.Scope] = Scopes.OpenId }));
        var verificationUri = authorization[DeviceAuthorizationResponse.Parameters.VerificationUri]!.GetValue<string>();
        var userCode = authorization[DeviceAuthorizationResponse.Parameters.UserCode]!.GetValue<string>();
        var deviceCode = authorization[DeviceAuthorizationResponse.Parameters.DeviceCode]!.GetValue<string>();
        Assert.Equal(Host + Acme + "/device", verificationUri);

        var entered = new Dictionary<string, string> { [DeviceAuthorizationResponse.Parameters.UserCode] = userCode };

        var atGlobex = await Http.PostAsync(
            Host + Globex + "/device", new FormUrlEncodedContent(entered), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, atGlobex.StatusCode);

        var atAcme = await Http.PostAsync(
            verificationUri, new FormUrlEncodedContent(entered), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, atAcme.StatusCode);

        var tokens = await PostAsync(Acme, TokenPath, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.DeviceAuthorization,
            [TokenRequest.Parameters.DeviceCode] = deviceCode,
        });
        Assert.Equal(HttpStatusCode.OK, tokens.StatusCode);
        var accessToken = (await ReadJsonAsync(tokens))[ResponseParameters.AccessToken]!.GetValue<string>();
        var payload = JsonNode.Parse(Base64Url.DecodeFromChars(accessToken.Split('.')[1]))!;
        Assert.Contains(AcmeResource, payload[IanaClaimTypes.Aud]!.ToJsonString(), StringComparison.Ordinal);
    }

}
