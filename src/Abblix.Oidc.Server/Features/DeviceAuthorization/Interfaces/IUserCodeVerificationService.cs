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
    /// context. Whatever this carries is what the device is granted, verbatim: the library adds nothing to
    /// it.</param>
    /// <returns>
    /// A task that returns true if the approval was successful; false if the code is invalid or expired.
    /// </returns>
    /// <remarks>
    /// <c>authorization_details</c> are the host's to carry. The requested entries arrive on
    /// <see cref="ValidUserCode"/>, and the decision the user made about them belongs on this grant's
    /// <c>AuthorizationContext</c> - narrowed, enriched or dropped, as the verification page decided. The
    /// library does not copy them across, because only that page knows what it displayed, and granting a
    /// payment nobody was shown is worse than granting none.
    /// <para>
    /// Approving with entries on the record and none on the grant is therefore allowed and logged at
    /// warning level: RFC 9396 §7 has the server return what was granted, so the token that follows
    /// carries nothing for a resource server to enforce, and that is worth seeing in a log rather than
    /// discovering at the resource server.
    /// </para>
    /// </remarks>
    Task<bool> ApproveAsync(string userCode, AuthorizedGrant authorizedGrant);

    /// <summary>
    /// Denies the device authorization request.
    /// </summary>
    /// <param name="userCode">The user-entered verification code.</param>
    /// <returns>
    /// A task that returns true if the denial was successful; false if the code is invalid or expired.
    /// </returns>
    Task<bool> DenyAsync(string userCode);
}
