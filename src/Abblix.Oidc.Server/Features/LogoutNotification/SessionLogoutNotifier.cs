// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Notifies the clients recorded for a session, each through <see cref="ILogoutNotifier"/>.
/// </summary>
/// <param name="logger">Reports a client whose notification failed.</param>
/// <param name="sessionClients">Supplies the clients recorded for the session.</param>
/// <param name="issuerProvider">Supplies the issuer the notifications name.</param>
/// <param name="clientInfoProvider">Resolves each recorded client.</param>
/// <param name="logoutNotifier">Delivers the notification to one client.</param>
public partial class SessionLogoutNotifier(
    ILogger<SessionLogoutNotifier> logger,
    ISessionClientRegistry sessionClients,
    IIssuerProvider issuerProvider,
    IClientInfoProvider clientInfoProvider,
    ILogoutNotifier logoutNotifier) : ISessionLogoutNotifier
{
    /// <inheritdoc />
    public async Task<LogoutContext> NotifyClientsAsync(string sessionId, string subject)
    {
        var context = new LogoutContext(sessionId, subject, LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()));

        // Every notification is awaited, so the back-channel POST is actually sent before the request ends.
        var tasks = new List<Task>();
        foreach (var clientId in await sessionClients.GetClientsAsync(sessionId))
        {
            var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
            if (clientInfo == null)
                continue;

            tasks.Add(NotifyClientSafelyAsync(clientInfo, context));
        }
        await Task.WhenAll(tasks);

        return context;
    }

    /// <summary>
    /// Notifies a single client of the logout, isolating any failure. Back-channel and front-channel
    /// logout are best-effort: a client whose endpoint is unreachable (down, TLS failure, blocked) is
    /// logged for operator attention but must not fail the end-user's logout.
    /// </summary>
    private async Task NotifyClientSafelyAsync(ClientInfo clientInfo, LogoutContext context)
    {
        try
        {
            await logoutNotifier.NotifyClientAsync(clientInfo, context);
        }
        catch (Exception exception)
        {
            LogClientLogoutNotificationFailed(exception, clientInfo.ClientId);
        }
    }

    [LoggerMessage(
        EventId = LogEvents.Endpoints.EndSessionRequestProcessor.ClientNotificationFailed,
        Level = LogLevel.Error,
        Message = "Failed to deliver a logout notification to client {ClientId}; the user's logout still completes")]
    private partial void LogClientLogoutNotificationFailed(Exception exception, string ClientId);
}
