// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using RegistrationParameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// FAPI 2.0 Security Profile section 5.3.2.1 and FAPI 1.0 Part 2 section 5.2.2 have the server "only issue
/// sender-constrained access tokens", and the FAPI CIBA profile section 5.2.2 has it "not support CIBA push mode": a
/// push mode client is handed its tokens in a request the server sends to it, with no token request to bind them to.
/// The host enables every delivery mode, so the push mode is one the server supports and its refusal at the tenant
/// held to FAPI 2.0 is the profile's: the tenant holding its clients to no profile serves the same client.
/// </summary>
/// <remarks>
/// The push mode client reaches the FAPI 2.0 tenant the way a stored registration does, added after the server starts,
/// as one registered while no profile was in force: a tenant declaring it does not start.
/// </remarks>
public sealed class FapiCibaPushModeTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string AuthorizePath = "/connect/bc-authorize";
    private const string PushClientId = "push-client";
    private const string PingClientId = "ping-client";
    private const string LoginHint = "alice";
    private const string NotificationToken = "notification-token-1";

    private static readonly Uri NotificationEndpoint = new("https://client.example.com/ciba");

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
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddDynamicClientRegistration();
        builder.Services.AddBackChannelAuthentication();
        // FAPI 2.0 section 5.4.1 holds the tokens the server signs for itself to PS256, ES256 or EdDSA too
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints =
                OidcEndpoints.Base | OidcEndpoints.BackChannelAuthentication | OidcEndpoints.RegisterClient;
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
        builder.Services.Replace(
            ServiceDescriptor.Scoped<IUserDeviceAuthenticationHandler, ReachableUserDeviceHandler>());

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        var clients = _app.Services.GetRequiredService<IClientInfoManager>();
        Assert.True(await clients.TryAddClientAsync(
            FapiTenant,
            new RegisteredClient(CibaClient(PushClientId, BackchannelTokenDeliveryModes.Push), "acme-push-rat-id")));
        Assert.True(await clients.TryAddClientAsync(
            FapiTenant,
            new RegisteredClient(CibaClient(PingClientId, BackchannelTokenDeliveryModes.Ping), "acme-ping-rat-id")));
        Assert.True(await clients.TryAddClientAsync(
            PlainTenant,
            new RegisteredClient(CibaClient(PushClientId, BackchannelTokenDeliveryModes.Push), "globex-push-rat-id")));

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
    /// A CIBA client in <paramref name="deliveryMode"/>, authenticating with a private key JWT and signing its ID tokens
    /// PS256, so that the only part of it the FAPI 2.0 profile can refuse is its delivery mode.
    /// </summary>
    private static ClientInfo CibaClient(string clientId, string deliveryMode) => new(clientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
        AllowedGrantTypes = [GrantTypes.Ciba],
        AllowedResponseTypes = [],
        BackChannelTokenDeliveryMode = deliveryMode,
        BackChannelClientNotificationEndpoint = NotificationEndpoint,
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
        AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
    };

    /// <summary>
    /// The push mode client starts a backchannel authentication at the tenant held to no profile and is refused at the
    /// one held to FAPI 2.0, where it does not authenticate: invalid_client, as for any stored client the profile does
    /// not admit, so no request of it is stored and no token is ever pushed to it. The ping mode client of the FAPI 2.0
    /// tenant starts one, so the refusal is its delivery mode's and not its authentication or algorithms.
    /// </summary>
    [Theory]
    [InlineData(Globex, PushClientId, HttpStatusCode.OK, null)]
    [InlineData(Acme, PushClientId, HttpStatusCode.Unauthorized, ErrorCodes.InvalidClient)]
    [InlineData(Acme, PingClientId, HttpStatusCode.OK, null)]
    public async Task ThePushMode_IsRefusedAtTheFapi2Tenant(
        string tenant, string clientId, HttpStatusCode expected, string? expectedError)
    {
        using var response = await _http!.PostAsync(
            tenant + AuthorizePath,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.ClientNotificationToken] = NotificationToken,
                [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
                [ClientRequest.Parameters.ClientAssertion] = await AssertionAsync(Host + tenant, clientId),
            }),
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(expected == response.StatusCode, $"{response.StatusCode}: {body}");
        Assert.Equal(expectedError, JsonNode.Parse(body)![ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// The discovery document lists the push mode where a client can use it: at the tenant holding its clients to no
    /// profile and not at the one held to FAPI 2.0 (CIBA Core 1.0 section 4: "one or more of" the modes).
    /// </summary>
    [Theory]
    [InlineData(Globex, true)]
    [InlineData(Acme, false)]
    public async Task TheDiscoveryDocument_ListsThePushModeOnlyWhereAClientCanUseIt(string tenant, bool listed)
    {
        var document = JsonNode.Parse(await _http!.GetStringAsync(
            tenant + "/.well-known/openid-configuration", TestContext.Current.CancellationToken))!;
        var deliveryModes = document[ConfigurationResponse.Parameters.BackchannelTokenDeliveryModesSupported]!.AsArray()
            .Select(value => value!.GetValue<string>())
            .ToArray();

        // The mode a client of either tenant can use, so an empty or missing list cannot pass the row that lists none
        Assert.Contains(BackchannelTokenDeliveryModes.Poll, deliveryModes);
        Assert.Equal(listed, deliveryModes.Contains(BackchannelTokenDeliveryModes.Push));
    }

    /// <summary>
    /// A CIBA registration in the push mode is refused at the FAPI 2.0 tenant with invalid_client_metadata (RFC 7591
    /// section 3.2.2) and registered there in the ping mode; at the tenant holding its clients to no profile it is
    /// registered as it stands.
    /// </summary>
    [Theory]
    [InlineData(Acme, BackchannelTokenDeliveryModes.Push, HttpStatusCode.BadRequest)]
    [InlineData(Acme, BackchannelTokenDeliveryModes.Ping, HttpStatusCode.Created)]
    [InlineData(Globex, BackchannelTokenDeliveryModes.Push, HttpStatusCode.Created)]
    public async Task ARegistrationInThePushMode_IsRefusedAtTheFapi2Tenant(
        string tenant, string deliveryMode, HttpStatusCode expected)
    {
        var registration = new JsonObject
        {
            [RegistrationParameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt,
            [RegistrationParameters.Jwks] = JsonSerializer.SerializeToNode(
                new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)])),
            [RegistrationParameters.ResponseTypes] = new JsonArray(),
            [RegistrationParameters.GrantTypes] = new JsonArray { GrantTypes.Ciba },
            [RegistrationParameters.BackChannelTokenDeliveryMode] = deliveryMode,
            [RegistrationParameters.BackChannelClientNotificationEndpoint] = NotificationEndpoint.OriginalString,
            [RegistrationParameters.IdTokenSignedResponseAlg] = SigningAlgorithms.PS256,
        };

        var response = await _http!.PostAsync(
            tenant + "/connect/register",
            new StringContent(registration.ToJsonString(), Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(expected == response.StatusCode, $"{response.StatusCode}: {body}");
        if (expected == HttpStatusCode.BadRequest)
            Assert.Equal(ErrorCodes.InvalidClientMetadata, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// A private key JWT <paramref name="clientId"/> authenticates with at <paramref name="issuer"/>, naming it as the
    /// audience as a string, which FAPI 2.0 section 5.3.2.1 requires.
    /// </summary>
    private async Task<string> AssertionAsync(string issuer, string clientId)
    {
        var now = TimeProvider.System.GetUtcNow();
        return await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.PS256, KeyId = ClientKey.KeyId },
                Payload =
                {
                    Issuer = clientId,
                    Subject = clientId,
                    Audiences = [issuer],
                    JwtId = Guid.NewGuid().ToString("N"),
                    IssuedAt = now,
                    ExpiresAt = now.AddMinutes(1),
                },
            },
            ClientKey);
    }

    /// <summary>
    /// The end user's device, reached at once.
    /// </summary>
    private sealed class ReachableUserDeviceHandler(TimeProvider clock) : IUserDeviceAuthenticationHandler
    {
        public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
            TenantDefinition tenant,
            ValidBackChannelAuthenticationRequest request)
            => Task.FromResult<Result<AuthSession, OidcError>>(new AuthSession(
                request.Model.LoginHint!, Guid.NewGuid().ToString("N"), clock.GetUtcNow(), "local"));
    }
}
