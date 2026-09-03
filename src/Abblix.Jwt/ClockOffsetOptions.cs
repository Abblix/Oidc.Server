// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// How far ahead of this machine's clock a token's <c>iat</c> or <c>nbf</c> may be and still be
/// accepted.
/// </summary>
/// <remarks>
/// <para>
/// This is a property of the CLOCK, not of a call, which is why it lives here rather than on
/// <see cref="ValidationParameters"/>. Every token this process validates is compared against the
/// same clock, so a tolerance passed per call would have to be remembered at every construction
/// site - and the site that forgot it would refuse tokens the others accept, intermittently, on
/// whichever pair of machines happened to drift.
/// </para>
/// <para>
/// It is deliberately separate from <see cref="ValidationParameters.ClockSkew"/>, which is about
/// expiry: a caller extending how long an already-issued token stays usable is answering a
/// different question from how far into the future a token may claim to have been minted, and
/// conflating them lets a generous expiry window silently widen the freshness check.
/// </para>
/// </remarks>
public class ClockOffsetOptions
{
    /// <summary>
    /// Ten seconds by default, which is the value FAPI 2.0 Security Profile section 5.3.2.1 names:
    /// a server "shall accept JWTs with an <c>iat</c> or <c>nbf</c> timestamp between 0 and 10
    /// seconds in the future but shall reject JWTs with an <c>iat</c> or <c>nbf</c> timestamp
    /// greater than 60 seconds in the future".
    /// </summary>
    public TimeSpan Tolerance { get; set; } = TimeSpan.FromSeconds(10);
}
