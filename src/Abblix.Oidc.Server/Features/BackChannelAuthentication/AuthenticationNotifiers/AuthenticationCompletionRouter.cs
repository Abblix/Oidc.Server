// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Routes CIBA authentication completion to the appropriate mode-specific handler
/// (PollModeCompletionHandler, PingModeCompletionHandler, or PushModeCompletionHandler) based on the client's configured
/// backchannel_token_delivery_mode.
/// </summary>
/// <param name="logger">Logger for tracking completion events.</param>
/// <param name="clientInfoProvider">Provider for retrieving client information.</param>
/// <param name="serviceProvider">Service provider for resolving mode-specific handlers using keyed services.</param>
/// <param name="subjectTypeConverter">
/// Seals the authenticated session's subject the way the requesting client sees it, so it can be compared
/// against the end user the request named.
/// </param>
/// <param name="storage">Records the refusal, so a client polling afterwards is told rather than left waiting.</param>
public partial class AuthenticationCompletionRouter(
    ILogger<AuthenticationCompletionRouter> logger,
    IClientInfoProvider clientInfoProvider,
    IServiceProvider serviceProvider,
    ISubjectTypeConverter subjectTypeConverter,
    IBackChannelRequestStorage storage) : IAuthenticationCompletionHandler
{
    private static readonly string[] AllDeliveryModes =
    [
        BackchannelTokenDeliveryModes.Poll,
        BackchannelTokenDeliveryModes.Ping,
        BackchannelTokenDeliveryModes.Push,
    ];

    /// <summary>
    /// Gets the list of supported token delivery modes by checking which handlers are registered in DI.
    /// This ensures the discovery document accurately reflects available functionality.
    /// </summary>
    public IEnumerable<string> TokenDeliveryModesSupported => AllDeliveryModes.Where(
        mode => serviceProvider.GetKeyedService<AuthenticationCompletionHandler>(mode) != null);

    /// <summary>
    /// Completes the authentication process and handles token delivery based on the
    /// client's configured delivery mode. Automatically selects the appropriate handler implementation.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id to complete.</param>
    /// <param name="request">The authentication request to mark as completed.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    public async Task CompleteAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        var clientId = request.AuthorizedGrant.Context.ClientId;
        var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId);

        if (clientInfo == null)
        {
            LogClientNotFound(authenticationRequestId, clientId);
            return;
        }

        // The end user authenticated out of band, and whoever the host reports now has to be the one the
        // request asked about. OpenID Connect Core 1.0 Section 3.1.2.2: the server "MUST NOT reply with an
        // ID Token or Access Token for a different user, even if they have an active session with the
        // Authorization Server". This is the only place every delivery mode passes through, and it is the
        // last point before tokens are minted or pushed, so a host that replaced the session on the stored
        // request - which is the shape IUserDeviceAuthenticationHandler documents - is judged here.
        //
        // Refused as denied rather than by throwing, because the caller is the host's own completion code
        // and has no protocol answer to give: recording the outcome is what reaches the client, which polls
        // and is told access_denied.
        if (request.RequestedSubject is { Length: > 0 } named &&
            !subjectTypeConverter.Names(request.AuthorizedGrant.AuthSession, [named], clientInfo))
        {
            LogAuthenticatedUserNotTheOneRequested(authenticationRequestId, clientId);

            request.Status = BackChannelAuthenticationStatus.Denied;
            await storage.UpdateAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        var deliveryMode = clientInfo.BackChannelTokenDeliveryMode.NotNull(nameof(clientInfo.BackChannelTokenDeliveryMode));
        var handler = serviceProvider.GetRequiredKeyedService<AuthenticationCompletionHandler>(deliveryMode);
        await handler.CompleteAuthenticationAsync(authenticationRequestId, request, clientInfo, expiresIn);
    }
}
