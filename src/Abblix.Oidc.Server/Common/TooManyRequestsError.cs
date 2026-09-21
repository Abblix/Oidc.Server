// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Subtype of <see cref="OidcError"/> that signals a caller which has spent its budget of requests: the endpoint
/// stopped before reading the token it was sent. It travels out as HTTP 429 with a <c>Retry-After</c> header
/// carrying <see cref="RetryAfter"/>, so the caller is told how long the refusal lasts rather than left to guess.
/// </summary>
/// <param name="ErrorDescription">What the caller exceeded, in the words of the endpoint that refused it.</param>
/// <param name="RetryAfter">
/// How long before the budget is available again, as the limiter reports it. Null when the limiter names no
/// interval, and then the response carries no <c>Retry-After</c>.
/// </param>
/// <remarks>
/// The status and the header carry the whole answer: the response has no body, because no registered OAuth error
/// code describes a caller that has asked too often, and a code that means something else is worse than none.
/// <c>slow_down</c> is defined for a client polling for an authorization that is still pending and tells it to
/// poll at a longer interval; <c>temporarily_unavailable</c> exists because a status code cannot travel through
/// an authorization redirect, and a client reading it may send its end user through the browser again. The code
/// this record carries is what the server logs the refusal as, and never what a caller is told.
/// </remarks>
public sealed record TooManyRequestsError(string ErrorDescription, TimeSpan? RetryAfter)
    : OidcError(ErrorCodes.TemporarilyUnavailable, ErrorDescription);
