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
/// <param name="statusNotifier">Wakes a client waiting on a long poll. Nullable because a deployment may
/// register none, NOT because long-polling is off: the default registration is unconditional, so this is
/// normally present even where the setting is disabled - the waiting is what the setting decides, and a
/// notification nobody waits for is a no-op.</param>
public partial class PollModeCompletionHandler(
    ILogger<PollModeCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    ISubjectTypeConverter subjectTypeConverter,
    IBackChannelLongPollingService? statusNotifier)
    : AuthenticationCompletionHandler(logger, storage, subjectTypeConverter, statusNotifier)
{
    /// <summary>
    /// Handles poll mode token delivery by storing the authenticated request in storage.
    /// The client will periodically poll the token endpoint to retrieve tokens, and one already waiting
    /// on a long poll is woken by the write.
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
        await StoreAsync(authenticationRequestId, request, expiresIn);

        LogTokensStored(authenticationRequestId);
    }
}
