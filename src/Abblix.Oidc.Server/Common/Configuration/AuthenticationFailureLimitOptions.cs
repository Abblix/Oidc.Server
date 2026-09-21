// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// How many client authentications may fail from one source address within a window before the token-reading
/// endpoints stop trying to authenticate callers from it.
/// </summary>
/// <remarks>
/// The budget one client gets cannot cover this: it is charged once the caller has proven which client it is,
/// and a sender that never authenticates successfully never reaches it. What such a sender costs is real -
/// a client authenticating with a signed assertion has its signature verified on every attempt, so a stream of
/// well-formed rubbish naming a registered client buys one verification per request. Counting the failures is
/// what puts a bound on it, and the source address is the only thing an unauthenticated sender cannot choose.
/// <para>
/// A working client never approaches this: its authentications succeed, and nothing successful is counted. What
/// the number has to clear is a deployment's own noise - a rotated secret, a clock skew, a misconfigured
/// instance retrying - which is why it is stated per minute rather than per second.
/// </para>
/// <para>
/// Two things a deployment has to know. Behind a reverse proxy the source address is the proxy's unless the
/// host configures forwarded headers, and then every caller shares one budget: a stranger's failures are then
/// charged to the same address as everyone else's, and once it is spent nobody's credentials are looked at
/// until the window turns. A deployment in that shape configures forwarded headers, raises the number, or sets
/// it to null. And a sender that rotates addresses is not bounded by this at all - as with any count against an
/// address, what it buys is a cost on the cheapest form of the attack, not an answer to every form.
/// </para>
/// </remarks>
public record AuthenticationFailureLimitOptions
{
    /// <summary>
    /// How many authentications may fail from one address within <see cref="Window"/>. Null lifts the limit,
    /// and every request has its credentials looked at however many have failed, as versions before this
    /// setting did.
    /// </summary>
    public int? PermitLimit { get; set; } = 100;

    /// <summary>
    /// The window failures are counted over. A minute by default, long enough that a deployment's own noise
    /// does not look like an attack and short enough that a source refused by mistake is not refused for long.
    /// </summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}
