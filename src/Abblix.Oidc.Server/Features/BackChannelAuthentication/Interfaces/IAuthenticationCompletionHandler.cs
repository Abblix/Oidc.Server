// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Handles CIBA authentication completion by routing to the appropriate delivery mode handler
/// (poll, ping, or push) based on the client's configured backchannel_token_delivery_mode.
/// </summary>
public interface IAuthenticationCompletionHandler
{
    /// <summary>
    /// Token delivery modes (poll, ping, push) for which a handler is registered with the DI container.
    /// Used to populate the discovery document's <c>backchannel_token_delivery_modes_supported</c> field
    /// so it reflects only modes the host actually supports.
    /// </summary>
    IEnumerable<string> TokenDeliveryModesSupported { get; }

    /// <summary>
    /// Completes the authentication process and handles token delivery according to
    /// the client's configured delivery mode.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <param name="request">The authentication request carrying the grant the end user approved. Its
    /// own Status is not read: whether this request may still be answered is decided from the STORED
    /// record, so a caller cannot make the decision by setting a field on its own copy.</param>
    /// <exception cref="InvalidOperationException">The stored record is not pending - it was already
    /// answered, or a poll has redeemed and removed it. Completing again would deliver a second answer
    /// for one authentication; recovering from a failed delivery means asking the end user.</exception>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    /// <returns>A task representing the asynchronous completion operation.</returns>
    /// <remarks>
    /// This method automatically:
    /// <list type="bullet">
    ///   <item>Retrieves client information to determine the delivery mode</item>
    ///   <item>Selects the appropriate handler (PollModeCompletionHandler, PingModeCompletionHandler, or PushModeCompletionHandler)</item>
    ///   <item>Delegates to the mode-specific implementation for token delivery</item>
    /// </list>
    /// </remarks>
    Task CompleteAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn);
}
