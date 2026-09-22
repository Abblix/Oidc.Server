// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// How many client authentications may fail from one source address within a window before this server stops
/// trying to authenticate callers from it, at every endpoint that authenticates a client.
/// </summary>
/// <remarks>
/// The budget one client gets cannot cover this: it is charged once the caller has proven which client it is,
/// and a sender whose credentials never verify never reaches it while still costing a signature verification
/// per attempt. The source address is the only thing such a sender cannot choose.
/// <para>
/// Nothing successful is counted, so what the number has to clear is a deployment's own noise - a rotated
/// secret, a clock skew, a misconfigured instance retrying - which is why it is stated per minute.
/// </para>
/// <para>
/// It is OFF until a deployment turns it on. A server whose callers reach it through a load balancer, an
/// ingress or a NAT gateway sees one address for all of them, and this budget is then one bucket for the whole
/// deployment, which anybody could spend with a hundred wrong secrets a minute. Turning it on states that this
/// server sees the addresses its callers come from.
/// </para>
/// <para>
/// A sender that rotates addresses is not bounded by it, and one that can choose the address this server sees
/// can both evade it and spend somebody else's budget.
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
