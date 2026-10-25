// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Oidc.Client.Features.EndSession;

/// <summary>
/// Builds the address that sends the user to the provider to end their session there
/// (OpenID Connect RP-Initiated Logout 1.0).
/// </summary>
/// <remarks>
/// Ending the session at this client is the host's own business and happens whatever the provider does with
/// this request. What this builder produces is the second half: telling the provider the user is leaving, so
/// the next visit is not signed straight back in from a session that outlived the local one.
/// </remarks>
public interface IEndSessionRequestBuilder
{
    /// <summary>
    /// Builds the logout address for the session the given ID Token belongs to.
    /// </summary>
    /// <param name="identityToken">
    /// The serialized ID Token this client last received for the session being ended, sent as
    /// <c>id_token_hint</c>.
    /// </param>
    /// <param name="state">
    /// An opaque value the provider echoes back to the post-logout address, when the caller wants to
    /// recognise the return. Optional.
    /// </param>
    /// <param name="logoutHint">
    /// A hint about which end-user is logging out, in whatever form the provider documents. Optional.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The address to send the user's browser to.</returns>
    /// <remarks>
    /// The ID Token is asked for rather than left optional, although the specification marks
    /// <c>id_token_hint</c> RECOMMENDED, because of what its absence costs the user. RP-Initiated Logout 1.0
    /// section 6: "Logout requests without a valid id_token_hint value are a potential means of denial of
    /// service; therefore, OPs should obtain explicit confirmation from the End-User before acting upon
    /// them." A client that omits it turns every sign-out into an extra page asking the user whether they
    /// really meant it.
    /// </remarks>
    /// <exception cref="EndSessionRequestException">
    /// The provider publishes no end-session endpoint, or the configured post-logout address is unusable.
    /// </exception>
    Task<Uri> CreateAsync(
        string identityToken,
        string? state = null,
        string? logoutHint = null,
        CancellationToken cancellationToken = default);
}
