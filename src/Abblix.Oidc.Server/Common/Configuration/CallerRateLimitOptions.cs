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
/// the next one, and a flood of introspection calls leaves revocation answering. A public client proves nothing,
/// its <c>client_id</c> being there for anyone to copy, so introspection turns it away outright and revocation
/// counts it by that identifier paired with the address the request came from.
/// <para>
/// That pairing is worth only what an address is worth where this server runs. Behind a load balancer, an
/// ingress or a NAT gateway every caller arrives from one address, so all the users of one public client share
/// a single budget, and a number chosen for one user's logout will refuse theirs. A deployment in that shape
/// sizes <see cref="PermitLimit"/> for the crowd behind the gateway, or has the gateway pass the caller's
/// address on. A sender that changes address on every request is not bounded by the pairing at all.
/// </para>
/// <para>
/// It is on out of the box, with a limit far above what a working deployment reaches. A deployment whose own
/// numbers are higher raises <see cref="PermitLimit"/>; one that wants no limit at all sets it to null.
/// </para>
/// <para>
/// These numbers are read once, when the limiter for an endpoint is first needed, so a change to them takes
/// effect on the next start rather than on a configuration reload. A deployment that needs a policy this cannot
/// express registers its own limiter instead, which the endpoints spend in place of these settings.
/// </para>
/// </remarks>
public record CallerRateLimitOptions
{
    /// <summary>
    /// How many requests one client may make within <see cref="Window"/>. Null lifts the limit, and the endpoints
    /// then answer every request the caller can send.
    /// </summary>
    /// <remarks>
    /// It belongs to a registered client, so a fleet of gateways introspecting under a single <c>client_id</c>
    /// shares one budget rather than holding one each. And it is counted inside one instance of this server, so
    /// a deployment running several multiplies it: a ceiling meant to hold across the fleet is divided by the
    /// number of instances before it is set here.
    /// </remarks>
    public int? PermitLimit { get; set; } = 10_000;

    /// <summary>
    /// The window <see cref="PermitLimit"/> is counted over. One second by default: a window that short keeps the
    /// refusal close to the burst that caused it, so a client that merely spiked is let through again almost at
    /// once, while one that keeps hammering stays refused.
    /// </summary>
    /// <remarks>
    /// Requests are counted per window rather than over a span that slides, so a client can spend a whole budget
    /// at the end of one window and another at the start of the next. What that costs is a burst of twice the
    /// limit across a window boundary; what it buys is a count that needs no per-request history.
    /// </remarks>
    public TimeSpan Window { get; set; } = TimeSpan.FromSeconds(1);
}
