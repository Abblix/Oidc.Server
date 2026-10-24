// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants each registering a client under the same id, one taking its tokens pushed and the other polling for
/// them: a decoupled authentication started at one tenant and completed by the host is delivered as that tenant's
/// client takes it, and only when the host completes it inside that tenant's scope.
/// </summary>
public sealed class CibaTenantIsolationTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "shared-client-id";
    private const string ClientSecret = "shared-client-secret";
    private const string AuthorizePath = "/connect/bc-authorize";
    private const string LoginHint = "alice";
    private const string NotificationToken = "notification-token";

    private readonly NotificationRecorder _deliveries = new();
    private WebApplication? _app;
    private HttpClient? _http;

    private HttpClient Http => _http!;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<IUserInfoProvider, SignedInUserInfo>();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddBackChannelAuthentication();
        builder.Services.AddOidcServices(options =>
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.BackChannelAuthentication);
        builder.Services.Replace(
            ServiceDescriptor.Scoped<IUserDeviceAuthenticationHandler, ReachableUserDeviceHandler>());

        // Where the server posts a push client's tokens, read back instead of sent
        builder.Services
            .AddHttpClient(BackChannelNotificationTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => _deliveries);

        builder.Services.Configure<OidcOptions>(options =>
        {
            options.Tenants.Add(Tenant("acme", Acme, BackchannelTokenDeliveryModes.Push));
            options.Tenants.Add(Tenant("globex", Globex, BackchannelTokenDeliveryModes.Poll));
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
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

    private static TenantDefinition Tenant(string id, string path, string deliveryMode) => new()
    {
        Id = id,
        Issuer = new Uri(Host + path),
        Clients =
        [
            new ClientInfo(ClientId)
            {
                ClientSecrets =
                [
                    new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
                ],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                AllowedGrantTypes = [GrantTypes.Ciba],
                AllowedResponseTypes = [],
                BackChannelTokenDeliveryMode = deliveryMode,
                BackChannelClientNotificationEndpoint =
                    deliveryMode == BackchannelTokenDeliveryModes.Poll ? null : NotificationEndpointOf(id),
            },
        ],
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static Uri NotificationEndpointOf(string tenantId) => new($"https://{tenantId}.client.example.com/ciba");

    /// <summary>
    /// Starts a decoupled authentication of the client at <paramref name="tenant"/> and returns its auth_req_id.
    /// </summary>
    private async Task<string> InitiateAtAsync(string tenant)
    {
        using var response = await Http.PostAsync(
            tenant + AuthorizePath,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.ClientNotificationToken] = NotificationToken,
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(response.IsSuccessStatusCode, $"backchannel authentication should start: {body}");
        return body["auth_req_id"]!.GetValue<string>();
    }

    /// <summary>
    /// Completes <paramref name="authenticationRequestId"/> as the host does when the end user approves on their
    /// device: reads the stored request inside <paramref name="readIn"/>'s scope and hands it to the completion
    /// handler inside <paramref name="completeIn"/>'s scope, or outside any scope when that is null.
    /// </summary>
    private async Task CompleteAsync(string authenticationRequestId, TenantDefinition readIn, TenantDefinition? completeIn)
    {
        Features.BackChannelAuthentication.BackChannelAuthenticationRequest completed;
        using (TenantScope.Enter(readIn))
        {
            using var reading = _app!.Services.CreateScope();
            var stored = await reading.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>()
                .TryGetAsync(authenticationRequestId);
            Assert.NotNull(stored);

            var session = new AuthSession(
                LoginHint, "session-1", TimeProvider.System.GetUtcNow(), "local");
            completed = stored with
            {
                AuthorizedGrant = new AuthorizedGrant(session, stored.AuthorizedGrant.Context),
            };
            completed.Status = BackChannelAuthenticationStatus.Authenticated;
        }

        using var scope = completeIn is null ? null : TenantScope.Enter(completeIn);
        using var completing = _app.Services.CreateScope();
        await completing.ServiceProvider.GetRequiredService<IAuthenticationCompletionHandler>()
            .CompleteAsync(authenticationRequestId, completed, TimeSpan.FromMinutes(5));
    }

    private async Task<TenantDefinition> TenantAsync(string id)
        => (await _app!.Services.GetRequiredService<ITenantCatalog>()
            .FindByIdAsync(id, TestContext.Current.CancellationToken))!;

    /// <summary>
    /// A request started at one tenant and completed by the host inside the other tenant's scope, or outside any
    /// scope, is refused and delivered nowhere; completed inside its own tenant's scope it reaches that tenant's
    /// client alone, pushed as that client takes it rather than as the other tenant's client of the same id would.
    /// </summary>
    [Fact]
    public async Task ARequestOfOneTenant_IsCompletedOnlyInItsScope_AndReachesItsClientAlone()
    {
        var acme = await TenantAsync("acme");
        var globex = await TenantAsync("globex");
        var authenticationRequestId = await InitiateAtAsync(Acme);

        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => CompleteAsync(authenticationRequestId, acme, globex));
        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => CompleteAsync(authenticationRequestId, acme, null));
        Assert.Empty(_deliveries.Received);

        await CompleteAsync(authenticationRequestId, acme, acme);

        var delivery = Assert.Single(_deliveries.Received);
        Assert.Equal(NotificationEndpointOf("acme"), delivery.Endpoint);
        Assert.False(string.IsNullOrEmpty(delivery.Payload["access_token"]?.GetValue<string>()));
        Assert.Null(delivery.Payload["error"]);
    }

    /// <summary>
    /// The end user the request names is always reachable on their device, so a decoupled authentication can start.
    /// </summary>
    private sealed class ReachableUserDeviceHandler(TimeProvider clock) : IUserDeviceAuthenticationHandler
    {
        public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
            ValidBackChannelAuthenticationRequest request)
            => Task.FromResult<Result<AuthSession, OidcError>>(new AuthSession(
                request.Model.LoginHint!, Guid.NewGuid().ToString("N"), clock.GetUtcNow(), "local"));
    }

    /// <summary>What the server posted to a client's notification endpoint, and where.</summary>
    private sealed record Delivery(Uri Endpoint, JsonObject Payload);

    /// <summary>
    /// Stands in for the clients' notification endpoints: answers 200 to every POST and keeps where it went and what
    /// it carried.
    /// </summary>
    private sealed class NotificationRecorder : HttpMessageHandler
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<Delivery> _received = new();

        public IEnumerable<Delivery> Received => _received;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var payload = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
            _received.Enqueue(new Delivery(request.RequestUri!, payload));
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
