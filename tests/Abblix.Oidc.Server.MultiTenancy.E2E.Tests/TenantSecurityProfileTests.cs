// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Http;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;


namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Each tenant holds its clients to the security profile it declares, and no other tenant's.
/// </summary>
/// <remarks>
/// A server of its own rather than the isolation suite's, because a strict profile refuses the plain client that
/// suite relies on at every tenant that declares it. That refusal comes at startup for a client a tenant declares,
/// so the client here reaches the strict tenant the way a stored registration does: added after the server
/// starts, as one registered dynamically before the profile was put in force.
/// </remarks>
public sealed class TenantSecurityProfileTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "shared-client-id";
    private const string ClientSecret = "shared-client-secret";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri both tenants' clients register; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private static readonly TenantDefinition GlobexTenant = new()
    {
        Id = "globex",
        Issuer = new Uri(Host + Globex),
        DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static readonly TenantDefinition AcmeTenant = new()
    {
        Id = "acme",
        Issuer = new Uri(Host + Acme),
        Clients = [Client()],
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
        builder.Services.AddSingleton<IUserInfoProvider, SignedInUserInfo>();
        // FAPI 2.0 section 5.4.1 holds the tokens the server signs for itself to PS256, ES256 or EdDSA too, and the
        // globex tenant holds its clients to FAPI 2.0
        builder.Services.AddOidcServices(options =>
        {
            options.ServiceTokens.AccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RefreshToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RegistrationAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.InitialAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
        });
        builder.Services.Configure<OidcOptions>(options =>
        {
            options.Tenants.Add(AcmeTenant);
            options.Tenants.Add(GlobexTenant);
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        Assert.True(await _app.Services.GetRequiredService<IClientInfoManager>()
            .TryAddClientAsync(GlobexTenant, new RegisteredClient(Client(), "registration-access-token-id")));

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
        ClientSecrets = [new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) }],
        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
        AllowedGrantTypes = [GrantTypes.AuthorizationCode],
        RedirectUris = [new Uri(RedirectUri)],
        PkceRequired = true,
    };

    /// <summary>
    /// A client authenticating with a shared secret is let in at the tenant without a profile, and refused at the
    /// tenant holding its clients to FAPI 2.0, which admits only a private key or a certificate.
    /// </summary>
    [Fact]
    public async Task AStrictProfile_BindsOnlyTheTenantThatDeclaresIt()
    {
        Task<HttpResponseMessage> PushAsync(string tenant) => _http!.PostAsync(
            tenant + "/connect/par",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [AuthorizationRequest.Parameters.CodeChallenge] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, (await PushAsync(Acme)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PushAsync(Globex)).StatusCode);
    }

    /// <summary>
    /// FAPI 2.0 Security Profile section 5.3.4: a resource server "shall not accept access tokens in the query
    /// parameters". The tenant holding its clients to FAPI 2.0 answers a token in the userinfo query with
    /// invalid_request and 400 (RFC 6750 section 3.1), and answers the same token in the Authorization header and in
    /// the form-encoded body.
    /// </summary>
    [Fact]
    public async Task AStrictProfile_RefusesTheAccessTokenInTheUserInfoQuery()
    {
        var accessToken = await _app!.Services.GetRequiredService<IAccessTokenService>().CreateAccessTokenAsync(
            GlobexTenant,
            new AuthSession(
                "user-1", "session-1", _app.Services.GetRequiredService<TimeProvider>().GetUtcNow(), "local"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], requestedClaims: null),
            Client(),
            grantId: null,
            expiresNoLaterThan: null);

        var inQuery = await _http!.GetAsync(
            $"{Globex}/connect/userinfo?{UserInfoRequest.Parameters.AccessToken}={accessToken.EncodedJwt}",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, inQuery.StatusCode);
        Assert.Contains(
            ErrorCodes.InvalidRequest,
            await inQuery.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var inHeader = new HttpRequestMessage(HttpMethod.Get, $"{Globex}/connect/userinfo");
        inHeader.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken.EncodedJwt);
        var response = await _http.SendAsync(inHeader, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The clause names the query alone, so the form-encoded body of RFC 6750 section 2.2 stays a way in
        var inForm = await _http.PostAsync(
            $"{Globex}/connect/userinfo",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [UserInfoRequest.Parameters.AccessToken] = accessToken.EncodedJwt,
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, inForm.StatusCode);
    }

    /// <summary>
    /// FAPI 2.0 Security Profile section 5.3.4: a resource server shall "verify that the authorization represented by
    /// the access token is sufficient for the requested resource access and otherwise return errors as in Section 3.1
    /// of [RFC6750]". The UserInfo Endpoint serves a token "obtained through OpenID Connect Authentication" (OpenID
    /// Connect Core 1.0 section 5.3), so a token without the openid scope is answered insufficient_scope with 403.
    /// </summary>
    [Fact]
    public async Task ATokenWithoutTheOpenIdScope_IsRefusedAtUserInfoForInsufficientScope()
    {
        var accessToken = await _app!.Services.GetRequiredService<IAccessTokenService>().CreateAccessTokenAsync(
            GlobexTenant,
            new AuthSession(
                "user-1", "session-1", _app.Services.GetRequiredService<TimeProvider>().GetUtcNow(), "local"),
            new AuthorizationContext(ClientId, [Scopes.Profile], requestedClaims: null),
            Client(),
            grantId: null,
            expiresNoLaterThan: null);

        using var request = new HttpRequestMessage(HttpMethod.Get, $"{Globex}/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken.EncodedJwt);
        var response = await _http!.SendAsync(request, TestContext.Current.CancellationToken);

        // RFC 6750 section 3.1 gives 403 to insufficient_scope alone, and the response carries no body to read it from
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// FAPI 2.0 Security Profile section 5.4.1 has the server use PS256, ES256 or EdDSA "when creating or processing
    /// JWTs", and a DPoP proof is one it processes. At a tenant naming no profile, a proof signed ES384, which RFC 9449
    /// admits, opens userinfo for a client naming none either, and is refused with invalid_dpop_proof for a client
    /// naming FAPI 2.0 for itself, whose ES256 proof opens it.
    /// </summary>
    [Fact]
    public async Task ADPoPProofIsJudgedAtUserInfoByTheProfileOfTheTokensClient()
    {
        const string fapiClientId = "fapi-client-id";
        Assert.True(await _app!.Services.GetRequiredService<IClientInfoManager>().TryAddClientAsync(
            AcmeTenant,
            new RegisteredClient(
                new ClientInfo(fapiClientId) { SecurityProfile = ClientSecurityProfile.Fapi2 },
                "fapi-registration-access-token-id")));

        using var es384 = new DPoPProofGenerator(algorithm: SigningAlgorithms.ES384);
        using var es256 = new DPoPProofGenerator();

        Assert.Equal(HttpStatusCode.OK, await UserInfoWithProofAsync(Client(), es384));
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            await UserInfoWithProofAsync(new ClientInfo(fapiClientId), es384));
        Assert.Equal(HttpStatusCode.OK, await UserInfoWithProofAsync(new ClientInfo(fapiClientId), es256));
    }

    /// <summary>
    /// Calls userinfo at the acme tenant with an access token issued to <paramref name="client"/> and bound to the key
    /// of <paramref name="proofKey"/>, presented with a proof that key signs.
    /// </summary>
    private async Task<HttpStatusCode> UserInfoWithProofAsync(ClientInfo client, DPoPProofGenerator proofKey)
    {
        var accessToken = await _app!.Services.GetRequiredService<IAccessTokenService>().CreateAccessTokenAsync(
            AcmeTenant,
            new AuthSession(
                "user-1", "session-1", _app.Services.GetRequiredService<TimeProvider>().GetUtcNow(), "local"),
            new AuthorizationContext(client.ClientId, [Scopes.OpenId], requestedClaims: null)
            {
                ProofKeyThumbprint = proofKey.Thumbprint,
            },
            client,
            grantId: null,
            expiresNoLaterThan: null);

        var endpoint = new Uri($"{Host}{Acme}/connect/userinfo");
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.DPoP, accessToken.EncodedJwt);
        request.Headers.Add(
            HttpRequestHeaders.DPoP,
            proofKey.BuildProof(HttpMethods.Get, endpoint, accessToken: accessToken.EncodedJwt));

        var response = await _http!.SendAsync(request, TestContext.Current.CancellationToken);
        return response.StatusCode;
    }
}
