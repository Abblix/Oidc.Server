// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;
using RegistrationParameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// FAPI 2.0 Security Profile section 5.3.2.1: authorization servers "shall reject requests using the resource owner
/// password credentials grant". The host enables the password grant, so the grant is one the server supports and its
/// refusal at the tenant held to FAPI 2.0 is the profile's: the tenant holding its clients to no profile registers the
/// same client and issues it a token.
/// </summary>
/// <remarks>
/// The client sending the password grant reaches the FAPI 2.0 tenant the way a stored registration does, added after
/// the server starts, as one registered while no profile was in force: a tenant declaring it does not start.
/// </remarks>
public sealed class Fapi2PasswordGrantTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "password-client";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri a registration names; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private static readonly RsaJsonWebKey ClientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly TenantDefinition FapiTenant = new()
    {
        Id = "acme",
        Issuer = new Uri(Host + Acme),
        DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static readonly TenantDefinition PlainTenant = new()
    {
        Id = "globex",
        Issuer = new Uri(Host + Globex),
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
        builder.Services.AddSingleton<IUserCredentialsAuthenticator, EveryUserAuthenticates>();
        builder.Services.EnablePasswordGrant();
        // FAPI 2.0 section 5.4.1 holds the tokens the server signs for itself to PS256, ES256 or EdDSA too
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.RegisterClient;
            options.RequireInitialAccessToken = false;
            options.ServiceTokens.AccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RefreshToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RegistrationAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.InitialAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
        });
        builder.Services.Configure<OidcOptions>(options =>
        {
            options.Tenants.Add(FapiTenant);
            options.Tenants.Add(PlainTenant);
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        var clients = _app.Services.GetRequiredService<IClientInfoManager>();
        Assert.True(await clients.TryAddClientAsync(FapiTenant, new RegisteredClient(PasswordClient(), "acme-rat-id")));
        Assert.True(await clients.TryAddClientAsync(PlainTenant, new RegisteredClient(PasswordClient(), "globex-rat-id")));

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    /// <summary>
    /// A client of the password grant alone, authenticating with a private key JWT and binding its tokens with DPoP, so
    /// that the only part of it the FAPI 2.0 profile refuses is the grant.
    /// </summary>
    private static ClientInfo PasswordClient() => new(ClientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
        AllowedGrantTypes = [GrantTypes.Password],
        AllowedResponseTypes = [],
        RequireDPoP = true,
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
        AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
    };

    /// <summary>
    /// The same password grant request from the same client is answered with a token at the tenant held to no profile
    /// and refused at the tenant held to FAPI 2.0, where the client does not authenticate: invalid_client, as for any
    /// stored client the profile does not admit.
    /// </summary>
    [Theory]
    [InlineData(Globex, HttpStatusCode.OK, null)]
    [InlineData(Acme, HttpStatusCode.Unauthorized, ErrorCodes.InvalidClient)]
    public async Task ThePasswordGrant_IsRefusedAtTheFapi2Tenant(
        string tenant, HttpStatusCode expected, string? expectedError)
    {
        var endpoint = new Uri(Host + tenant + "/connect/token");
        using var proofKey = new DPoPProofGenerator();
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Add(HttpRequestHeaders.DPoP, proofKey.BuildProof(HttpMethods.Post, endpoint));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.Password,
            [TokenRequest.Parameters.Username] = "user-1",
            [TokenRequest.Parameters.Password] = "any-password",
            [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
            [ClientRequest.Parameters.ClientAssertion] = await AssertionAsync(Host + tenant),
        });

        var response = await _http!.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expectedError, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// A registration for the password grant beside the authorization code grant is refused at the FAPI 2.0 tenant
    /// with invalid_client_metadata, and registered there without it; at the tenant holding its clients to no profile
    /// it is registered as it stands.
    /// </summary>
    [Theory]
    [InlineData(Acme, true, HttpStatusCode.BadRequest)]
    [InlineData(Acme, false, HttpStatusCode.Created)]
    [InlineData(Globex, true, HttpStatusCode.Created)]
    public async Task ARegistrationForThePasswordGrant_IsRefusedAtTheFapi2Tenant(
        string tenant, bool password, HttpStatusCode expected)
    {
        var grantTypes = new JsonArray { GrantTypes.AuthorizationCode };
        if (password)
            grantTypes.Add(GrantTypes.Password);

        var registration = new JsonObject
        {
            [RegistrationParameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt,
            [RegistrationParameters.Jwks] = JsonSerializer.SerializeToNode(
                new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)])),
            [RegistrationParameters.RedirectUris] = new JsonArray { RedirectUri },
            [RegistrationParameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationParameters.GrantTypes] = grantTypes,
            [RegistrationParameters.IdTokenSignedResponseAlg] = SigningAlgorithms.PS256,
        };

        var response = await _http!.PostAsync(
            tenant + "/connect/register",
            new StringContent(registration.ToJsonString(), Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.BadRequest)
            Assert.Equal(ErrorCodes.InvalidClientMetadata, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// A private key JWT the client authenticates with at <paramref name="issuer"/>, naming it as the audience as a
    /// string, which FAPI 2.0 section 5.3.2.1 requires.
    /// </summary>
    private async Task<string> AssertionAsync(string issuer)
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
                    Audiences = [issuer],
                    JwtId = Guid.NewGuid().ToString("N"),
                    IssuedAt = now,
                    ExpiresAt = now.AddMinutes(1),
                },
            },
            ClientKey);
    }

    /// <summary>
    /// Takes every user name and password, so that what decides a request here is the profile and not the user.
    /// </summary>
    private sealed class EveryUserAuthenticates(TimeProvider timeProvider) : IUserCredentialsAuthenticator
    {
        public Task<Result<AuthorizedGrant, OidcError>> ValidateAsync(
            TenantDefinition tenant, string userName, string password, AuthorizationContext context)
            => Task.FromResult<Result<AuthorizedGrant, OidcError>>(new AuthorizedGrant(
                new AuthSession(userName, "session-1", timeProvider.GetUtcNow(), "local"),
                context));
    }
}
