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
/// the next one, and a flood of introspection calls leaves revocation answering. Only a caller that presented a
/// credential is counted, so nobody can spend a budget by naming a client they do not hold - which is why a
/// public client, whose only claim to its identity is a <c>client_id</c> anyone can copy, is never counted at
/// the revocation endpoint and is turned away outright at introspection.
/// <para>
/// It is on out of the box, with a limit far above what a working deployment reaches, because the request it
/// refuses is the one a compromised or looping client repeats without pause - and nobody switches a protection
/// on before they need it. A deployment whose own numbers are higher raises <see cref="PermitLimit"/>; one that
/// wants no limit at all sets it to null.
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
    /// then answer every request the caller can send, as versions before this setting did.
    /// </summary>
    /// <remarks>
    /// Two things decide what this number means in a deployment. It belongs to a registered client, so every
    /// instance of one resource server spends it together: a fleet of gateways introspecting under a single
    /// <c>client_id</c> shares one budget rather than holding one each. And it is counted inside one instance of
    /// this server, so a deployment running several multiplies it: with four instances behind a load balancer,
    /// a client that spreads its requests evenly is answered four times this number. A deployment that wants a
    /// ceiling of its own across the whole fleet therefore divides that ceiling by the number of instances and
    /// sets the result here; raising this number is for a client whose honest traffic is higher, not for a
    /// deployment that grew.
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
