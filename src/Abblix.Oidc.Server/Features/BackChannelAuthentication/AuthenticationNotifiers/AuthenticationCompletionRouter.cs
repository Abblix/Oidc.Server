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
public partial class AuthenticationCompletionRouter(
    ILogger<AuthenticationCompletionRouter> logger,
    IClientInfoProvider clientInfoProvider,
    IServiceProvider serviceProvider) : IAuthenticationCompletionHandler
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

        var deliveryMode = clientInfo.BackChannelTokenDeliveryMode.NotNull(nameof(clientInfo.BackChannelTokenDeliveryMode));
        var handler = serviceProvider.GetRequiredKeyedService<AuthenticationCompletionHandler>(deliveryMode);
        await handler.CompleteAuthenticationAsync(authenticationRequestId, request, clientInfo, expiresIn);
    }
}
