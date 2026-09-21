// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// How many requests one authenticated caller may make to the introspection and revocation endpoints within a
/// window before the endpoint refuses with 429 instead of reading the token it was sent.
/// </summary>
/// <remarks>
/// The budget is per client and per endpoint: a resource server that starts looping does not spend the budget of
/// the next one, and a flood of introspection calls leaves revocation answering. Both endpoints authenticate the
/// caller before anything is counted, so the partition key is a client this server issued credentials to rather
/// than anything an unauthenticated caller can make up.
/// <para>
/// It is on out of the box, with a limit far above what a working deployment reaches, because the request it
/// refuses is the one a compromised or looping client makes thousands of times a second - and nobody switches a
/// protection on before they need it. A deployment whose own numbers are higher raises
/// <see cref="PermitLimit"/>; one that wants no limit at all sets it to null.
/// </para>
/// </remarks>
public record CallerRateLimitOptions
{
    /// <summary>
    /// How many requests one client may make within <see cref="Window"/>. Null lifts the limit, and the endpoints
    /// then answer every request the caller can send, as versions before this setting did.
    /// </summary>
    public int? PermitLimit { get; set; } = 1000;

    /// <summary>
    /// The window <see cref="PermitLimit"/> is counted over. One second by default: a window that short keeps the
    /// refusal close to the burst that caused it, so a client that merely spiked is let through again almost at
    /// once, while one that keeps hammering stays refused.
    /// </summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromSeconds(1);
}
