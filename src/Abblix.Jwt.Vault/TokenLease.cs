// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault;

/// <summary>
/// What a successful login or renewal hands back: the token and how long its lease runs.
/// </summary>
/// <param name="Token">The client token to present on every request.</param>
/// <param name="LeaseDuration">How long the lease runs from now. Renewal happens well before it ends.</param>
/// <param name="Renewable">
/// Whether the token can be renewed at all. A batch token cannot, and for it the lifecycle skips renewal and
/// simply logs in again before the lease runs out.
/// </param>
internal sealed record TokenLease(string Token, TimeSpan LeaseDuration, bool Renewable);

/// <summary>
/// How a renewal attempt ended. The three outcomes drive three different reactions, which is why a bool
/// cannot carry the answer.
/// </summary>
internal enum RenewStatus
{
    /// <summary>The lease was extended. Read the new duration from the lease.</summary>
    Renewed,

    /// <summary>
    /// Vault refused the renewal outright. The token cannot be renewed - it lacks the permission or is a
    /// batch token - so the lifecycle stops asking and watches the clock until it is time to log in again.
    /// </summary>
    PermissionDenied,

    /// <summary>
    /// The attempt failed for a reason that may pass: a network error, a sealed or restarting server.
    /// The lifecycle retries with backoff while the current lease still runs.
    /// </summary>
    Failed,
}

/// <summary>
/// Verdict of a renewal attempt: the status, and the renewed lease when there is one.
/// </summary>
/// <param name="Status">How the attempt ended.</param>
/// <param name="Lease">The renewed lease when <paramref name="Status"/> is <see cref="RenewStatus.Renewed"/>.</param>
internal readonly record struct RenewResult(RenewStatus Status, TokenLease? Lease);
