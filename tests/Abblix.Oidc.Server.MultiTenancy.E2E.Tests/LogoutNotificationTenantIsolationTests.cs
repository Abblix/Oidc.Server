// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants each registering a client under the same id, and a user signed in to both: a logout at one tenant
/// notifies that tenant's client alone, over the front channel and the back channel, and only when that client
/// authorized in the user's session there.
/// </summary>
public sealed class LogoutNotificationTenantIsolationTests : IAsyncLifetime
{
    private const string Acme = SignedInTenantsHost.Acme;
    private const string Globex = SignedInTenantsHost.Globex;
    private const string EndSessionPath = "/connect/endsession";

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri both tenants' clients register; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private readonly RecordingLogoutTokenSender _backChannel = new();
    private SignedInTenantsHost? _host;

    private HttpClient Http => _host!.Http;

    public async ValueTask InitializeAsync()
        => _host = await SignedInTenantsHost.StartAsync(
            tenantId => new ClientInfo(SignedInTenantsHost.ClientId)
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                RedirectUris = [new Uri(RedirectUri)],
                PostLogoutRedirectUris = [new Uri(RedirectUri)],
                PkceRequired = true,
                FrontChannelLogout = new FrontChannelLogoutOptions(FrontChannelOf(tenantId)),
                BackChannelLogout = new BackChannelLogoutOptions(BackChannelOf(tenantId)),
            },
            services =>
            {
                services.AddFrontChannelLogout();
                services.AddBackChannelLogout();
                services.Replace(ServiceDescriptor.Singleton<ILogoutTokenSender>(_backChannel));
            });

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
            await _host.DisposeAsync();
    }

    private static Uri FrontChannelOf(string tenantId) => new($"https://{tenantId}.client.example.com/front-logout");

    private static Uri BackChannelOf(string tenantId) => new($"https://{tenantId}.client.example.com/back-logout");

    private Task AuthorizeAtAsync(string tenant) => _host!.CodeAtAsync(tenant, RedirectUri);

    /// <summary>
    /// Logs out at <paramref name="tenant"/> as a deployment's own page does: the first request is answered with the
    /// question, and the second carries the answer.
    /// </summary>
    private async Task<HttpResponseMessage> LogOutAtAsync(string tenant)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);
        query[EndSessionRequest.Parameters.ClientId] = SignedInTenantsHost.ClientId;
        query[EndSessionRequest.Parameters.PostLogoutRedirectUri] = RedirectUri;

        var asked = await Http.GetAsync($"{tenant}{EndSessionPath}?{query}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, asked.StatusCode);
        var question = JsonNode.Parse(await asked.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.ConfirmationRequired, question[ResponseParameters.Error]!.GetValue<string>());

        query[EndSessionRequest.Parameters.Confirmation] =
            question[EndSessionRequest.Parameters.Confirmation]!.GetValue<string>();
        return await Http.GetAsync($"{tenant}{EndSessionPath}?{query}", TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A logout at one tenant frames the front-channel logout page of that tenant's client alone, and sends a logout
    /// token to that tenant's client alone, though the other tenant's client of the same id is in the same session.
    /// </summary>
    [Fact]
    public async Task ALogoutAtOneTenant_NotifiesThatTenantsClientAlone()
    {
        await AuthorizeAtAsync(Acme);
        await AuthorizeAtAsync(Globex);

        using var loggedOut = await LogOutAtAsync(Acme);

        var page = await loggedOut.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(
            loggedOut.IsSuccessStatusCode,
            $"/endsession failed: {(int)loggedOut.StatusCode} {loggedOut.Headers.Location} {page}");
        Assert.Contains(FrontChannelOf("acme").OriginalString, page, StringComparison.Ordinal);
        Assert.DoesNotContain(FrontChannelOf("globex").OriginalString, page, StringComparison.Ordinal);
        Assert.Equal([BackChannelOf("acme")], _backChannel.Notified);
    }

    /// <summary>
    /// A logout at a tenant whose client never authorized in the user's session there notifies nobody, though the
    /// other tenant's client of the same id authorized in that session.
    /// </summary>
    [Fact]
    public async Task ALogoutAtATenantWhoseClientNeverAuthorized_NotifiesNobody()
    {
        await AuthorizeAtAsync(Globex);

        using var loggedOut = await LogOutAtAsync(Acme);

        var page = await loggedOut.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(FrontChannelOf("acme").OriginalString, page, StringComparison.Ordinal);
        Assert.DoesNotContain(FrontChannelOf("globex").OriginalString, page, StringComparison.Ordinal);
        Assert.Empty(_backChannel.Notified);
    }

    /// <summary>
    /// Records where each back-channel logout token is sent, in place of sending it.
    /// </summary>
    private sealed class RecordingLogoutTokenSender : ILogoutTokenSender
    {
        private readonly ConcurrentQueue<Uri> _notified = new();

        public IEnumerable<Uri> Notified => _notified;

        public Task SendBackChannelLogoutAsync(ClientInfo clientInfo, EncodedJsonWebToken logoutToken)
        {
            _notified.Enqueue(clientInfo.BackChannelLogout!.Uri);
            return Task.CompletedTask;
        }
    }
}
