// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;

/// <summary>
/// Defines the contract for a service that handles user code verification
/// in the Device Authorization Grant flow (RFC 8628).
/// </summary>
public interface IUserCodeVerificationService
{
    /// <summary>
    /// Verifies a user code and returns the associated device authorization request details.
    /// </summary>
    /// <param name="userCode">The user-entered verification code.</param>
    /// <returns>
    /// A task that returns the verification result containing request details if valid,
    /// or an appropriate error if the code is invalid, expired, or already used.
    /// </returns>
    Task<UserCodeVerificationResult> VerifyAsync(string userCode);

    /// <summary>
    /// Approves the device authorization request, linking the user's authorization to the pending device.
    /// </summary>
    /// <param name="userCode">The user-entered verification code.</param>
    /// <param name="authorizedGrant">The authorized grant containing the user's authentication session and
    /// context. Its <c>authorization_details</c> are what the device is granted: the library adds none, and
    /// refuses an approval carrying a type the request never asked for. Its scopes and resources are a
    /// starting point rather than the final word - the token endpoint narrows them against the token
    /// request (RFC 8707 section 2.2) and adds the certificate and proof-key confirmations.</param>
    /// <returns>
    /// True when this call is the one that recorded the approval. False otherwise, and otherwise is
    /// wider than a bad code: the stored record is re-read and must still be pending, so a denial or
    /// another approval landing first answers false too, as does a request whose lifetime ran out and
    /// one whose grant carries a type the request never asked for. The decision is not applied in any
    /// of those cases, and nothing about the record changes.
    /// <para>
    /// A true is not a guarantee that nothing landed in between. The re-read and the write are two
    /// store calls, and the store exposes no conditional write, so two concurrent approvals can each
    /// be told true and the later write wins. That window is one store round trip wide.
    /// </para>
    /// </returns>
    /// <remarks>
    /// <c>authorization_details</c> are the host's to carry. The requested entries arrive on
    /// <see cref="ValidUserCode"/>, and the decision the user made about them belongs on this grant's
    /// <c>AuthorizationContext</c> - narrowed, enriched or dropped, as the verification page decided. The
    /// library does not copy them across, because only that page knows what it displayed, and granting a
    /// payment nobody was shown is worse than granting none.
    /// <para>
    /// Approving with entries on the record and none on the grant is therefore allowed and logged at
    /// warning level. RFC 9396 section 7 is satisfied either way, since its MUST is to return what the
    /// resource owner GRANTED and nothing granted is nothing to return. What matters here is section 9 of
    /// that document: it makes the details reaching the resource server the point of having them, and a
    /// token carrying none leaves it nothing to enforce, which is worth seeing in a log rather than
    /// discovering at the resource
    /// server.
    /// </para>
    /// <para>
    /// The opposite direction is refused rather than logged. A grant carrying a type the device
    /// authorization request never asked for gives the device authority nobody requested, so the
    /// approval answers <c>false</c> and the request stays pending.
    /// </para>
    /// </remarks>
    Task<bool> ApproveAsync(string userCode, AuthorizedGrant authorizedGrant);

    /// <summary>
    /// Denies the device authorization request.
    /// </summary>
    /// <param name="userCode">The user-entered verification code.</param>
    /// <returns>
    /// True when this call is the one that recorded the denial. False otherwise, and otherwise is wider
    /// than a bad code: the stored record is re-read and must still be pending, so a decision that
    /// landed first answers false, as does a request whose lifetime ran out. Nothing about the record changes in those cases, and a true
    /// carries the same narrowed-not-closed window <see cref="ApproveAsync"/> describes.
    /// </returns>
    Task<bool> DenyAsync(string userCode);
}
