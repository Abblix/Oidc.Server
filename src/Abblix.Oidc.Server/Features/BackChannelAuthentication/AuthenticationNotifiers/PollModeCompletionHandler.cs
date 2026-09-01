// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Handles CIBA poll mode token delivery where the client periodically polls the token endpoint to retrieve tokens.
/// In poll mode, the authenticated request is stored and remains available until the client retrieves it or it expires.
/// Supports optional long-polling to reduce polling frequency and improve efficiency.
/// </summary>
/// <param name="logger">Logger for tracking notification events.</param>
/// <param name="storage">Storage for authentication requests.</param>
/// <param name="subjectTypeConverter">Seals a session's subject the way the requesting client sees it,
/// so the end user who authenticated can be compared against the one the request named.</param>
/// <param name="statusNotifier">Optional service for notifying long-polling clients of status changes.
/// Null when long-polling is disabled.</param>
public partial class PollModeCompletionHandler(
    ILogger<PollModeCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    ISubjectTypeConverter subjectTypeConverter,
    IBackChannelLongPollingService? statusNotifier)
    : AuthenticationCompletionHandler(logger, storage, subjectTypeConverter)
{
    private readonly IBackChannelRequestStorage _storage = storage;

    /// <summary>
    /// Handles poll mode token delivery by storing the authenticated request in storage.
    /// The client will periodically poll the token endpoint to retrieve tokens.
    /// If long-polling is enabled, also notifies any waiting clients of the status change.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information (not used in poll mode).</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    protected override async Task HandleDeliveryAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn)
    {
        await _storage.UpdateAsync(authenticationRequestId, request, expiresIn);

        LogTokensStored(authenticationRequestId);

        await NotifyAsync(authenticationRequestId, request.Status);
    }

    /// <summary>
    /// Refuses by denying, as the base class does, and then wakes whoever is waiting.
    /// </summary>
    /// <remarks>
    /// A denial is exactly as final as an approval, and the client learns about both the same way - by
    /// polling. Without this a request the end user rejected in a second answers only when the waiter's
    /// own long-poll window runs out, while the identical request they approved answers at once. The
    /// asymmetry has no reason behind it: this path already knows the status changed and already writes
    /// it.
    /// </remarks>
    protected override async Task RefuseAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        await DenyRequestAsync(authenticationRequestId, request, expiresIn);

        await NotifyAsync(authenticationRequestId, request.Status);
    }

    /// <summary>
    /// Wakes the waiters of one request, or does nothing when the deployment registered no notifier.
    /// </summary>
    /// <remarks>
    /// One place on purpose, so that a transition added later signals by construction rather than by
    /// somebody remembering: what the contract promises is that every transition THIS class performs
    /// reaches the notifier, which a list of call sites cannot keep true.
    /// </remarks>
    private async Task NotifyAsync(
        string authenticationRequestId,
        BackChannelAuthenticationStatus status)
    {
        if (statusNotifier == null)
            return;

        await statusNotifier.NotifyStatusChangeAsync(authenticationRequestId, status);
    }
}
