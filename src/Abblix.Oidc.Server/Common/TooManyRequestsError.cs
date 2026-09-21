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
/// The body says <c>temporarily_unavailable</c>, which states what happened to this request - the server is not
/// handling it because of load it attributes to this caller - and is a code every OAuth client library already
/// knows. The one alternative, <c>slow_down</c>, means something else: it is defined for a client polling for an
/// authorization that is still pending, and tells it to keep polling at a longer interval. Nothing is pending
/// here, and a client acting on that reading would poll an endpoint that answers in one call.
/// </remarks>
public sealed record TooManyRequestsError(string ErrorDescription, TimeSpan? RetryAfter)
    : OidcError(ErrorCodes.TemporarilyUnavailable, ErrorDescription);
