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
/// RFC 8628 Section 5.1 recommends that the server rate-limit user code attempts. The word there is
/// lowercase, so this is a mitigation the server chooses rather than one it inherits - and the choice
/// is what makes the entropy argument in that section hold.
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
    /// - Failure (<see cref="UserCodeRateLimited"/>): the attempt is refused, with how long before it may
    ///   be made again and whether the refusal follows from attempts against this very code - which decides
    ///   whether a caller may be told anything at all.
    /// </returns>
    Task<Result<bool, UserCodeRateLimited>> CheckAsync(string userCode, string clientIdentifier);

    /// <summary>
    /// Records a failed verification attempt for rate limiting purposes.
    /// </summary>
    /// <param name="userCode">The user code that failed verification.</param>
    /// <param name="clientIdentifier">The client identifier (IP address or other identifier).</param>
    Task RecordFailureAsync(string userCode, string clientIdentifier);

    /// <summary>
    /// Records a failed attempt at a user code that does not exist.
    /// </summary>
    /// <remarks>
    /// Deliberately not charged to the value that was typed. A guesser never submits the same value
    /// twice, so counting per value bounds nothing - and a count held against a value nobody was issued
    /// would be spent before a real code could ever carry it, leaving the person who reads that code off
    /// their screen unable to use it. What this attempt belongs to is the source that made it and the
    /// server's own budget for the window.
    /// </remarks>
    /// <param name="clientIdentifier">The client identifier (typically IP address) making the attempt.</param>
    /// <returns>A task that completes when the attempt has been recorded.</returns>
    Task RecordUnknownCodeAsync(string clientIdentifier);

    /// <summary>
    /// Records a successful verification to reset rate limiting counters.
    /// </summary>
    /// <param name="userCode">The user code that was successfully verified.</param>
    /// <param name="clientIdentifier">The client identifier (IP address or other identifier).</param>
    Task RecordSuccessAsync(string userCode, string clientIdentifier);
}
