// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
