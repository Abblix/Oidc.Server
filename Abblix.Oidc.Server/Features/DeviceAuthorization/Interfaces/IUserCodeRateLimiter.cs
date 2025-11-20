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

using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;

/// <summary>
/// Defines the contract for rate limiting user code verification attempts to prevent brute force attacks.
/// Per RFC 8628 Section 5.2, implementations SHOULD implement rate limiting to prevent abuse.
/// </summary>
public interface IUserCodeRateLimiter
{
    /// <summary>
    /// Checks if a verification attempt should be allowed for the given user code and client identifier.
    /// Implements exponential backoff and per-IP rate limiting to prevent brute force attacks.
    /// </summary>
    /// <param name="userCode">The user code being verified.</param>
    /// <param name="clientIdentifier">The client identifier (IP address or other identifier).</param>
    /// <returns>
    /// A <see cref="Result{TSuccess, TFailure}"/> containing:
    /// - Success (<c>true</c>): The verification attempt is allowed to proceed.
    /// - Failure (<see cref="TimeSpan"/>): The attempt is rate limited; the value indicates the duration
    ///   the client must wait before retrying (Retry-After).
    /// </returns>
    Task<Result<bool, TimeSpan>> CheckAsync(string userCode, string clientIdentifier);

    /// <summary>
    /// Records a failed verification attempt for rate limiting purposes.
    /// </summary>
    /// <param name="userCode">The user code that failed verification.</param>
    /// <param name="clientIdentifier">The client identifier (IP address or other identifier).</param>
    Task RecordFailureAsync(string userCode, string clientIdentifier);

    /// <summary>
    /// Records a successful verification to reset rate limiting counters.
    /// </summary>
    /// <param name="userCode">The user code that was successfully verified.</param>
    /// <param name="clientIdentifier">The client identifier (IP address or other identifier).</param>
    Task RecordSuccessAsync(string userCode, string clientIdentifier);
}
