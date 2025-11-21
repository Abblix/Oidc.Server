// Abblix OIDC Server Library
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
    /// <param name="authorizedGrant">The authorized grant containing the user's authentication session and context.</param>
    /// <returns>
    /// A task that returns true if the approval was successful; false if the code is invalid or expired.
    /// </returns>
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
