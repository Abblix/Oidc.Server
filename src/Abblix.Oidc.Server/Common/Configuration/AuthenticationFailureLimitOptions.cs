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
/// It is OFF until a deployment turns it on, which is the opposite of the budget one client gets, and the
/// reason is what an address means where this server runs. A server whose callers reach it through a load
/// balancer, an ingress or a NAT gateway sees one address for all of them, and then this budget is one bucket
/// for the whole deployment: anybody on the internet could spend it with a hundred wrong secrets a minute and
/// leave every honest client refused until the window turned. Turning it on is a statement that this server
/// sees the addresses its callers actually come from - which usually means it terminates their connections
/// itself, or its proxy is trusted to say so and nobody else is.
/// </para>
/// <para>
/// What it does not answer: a sender that rotates addresses is not bounded by it, as with any count against an
/// address, and a sender that can choose the address this server sees - which is what trusting a forwarded
/// header from anyone amounts to - can both evade it and spend somebody else's budget. What it buys is a price
/// on the cheapest form of the attack, from a deployment that knows what an address means to it.
/// </para>
/// </remarks>
public record AuthenticationFailureLimitOptions
{
    /// <summary>
    /// How many authentications may fail from one address within <see cref="Window"/>. Null, the default,
    /// counts nothing and every request has its credentials looked at however many have failed - unless the
    /// host registered a limiter of its own for this, which decides instead of these numbers.
    /// </summary>
    /// <remarks>
    /// Counted inside one instance of this server, like every other budget here, so a deployment running
    /// several multiplies it, and the number is read once when the limiter is first needed rather than on a
    /// configuration reload.
    /// </remarks>
    public int? PermitLimit { get; set; }

    /// <summary>
    /// The window failures are counted over. A minute by default, long enough that a deployment's own noise
    /// does not look like an attack and short enough that a source refused by mistake is not refused for long.
    /// </summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}
