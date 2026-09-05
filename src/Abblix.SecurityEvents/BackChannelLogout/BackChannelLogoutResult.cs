// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// What a back-channel logout request earns: the status code the transport answers with, and -
/// only beside a 400 - the error body the provider reads (OpenID Connect Back-Channel Logout 1.0
/// Section 2.8). The shape is transport-neutral on purpose: any host adapter renders it, none
/// decides it.
/// </summary>
/// <param name="StatusCode">The HTTP status the response carries.</param>
/// <param name="Error">
/// The error body of a failure response; null on success, whose body is empty.</param>
public sealed record BackChannelLogoutResult(HttpStatusCode StatusCode, BackChannelLogoutError? Error)
{
    /// <summary>
    /// The success: "If the logout succeeded, the RP MUST respond with HTTP 200 OK." A single
    /// shared instance, because success carries no request-specific state.
    /// </summary>
    /// <remarks>
    /// Section 2.8 notes that a framework may turn this into a 204 when the body is empty, and
    /// that providers should accept either. Which of the two goes out is therefore the host
    /// adapter's business, not a decision to make here.
    /// </remarks>
    public static BackChannelLogoutResult Ok { get; } = new(HttpStatusCode.OK, null);

    /// <summary>
    /// A rejection: "If the logout request was invalid or the logout failed, the RP MUST respond
    /// with HTTP 400 Bad Request."
    /// </summary>
    /// <param name="description">What was wrong, for an operator reading the provider's logs.</param>
    public static BackChannelLogoutResult BadRequest(string description)
        => new(
            HttpStatusCode.BadRequest,
            new BackChannelLogoutError(BackChannelLogoutError.InvalidRequest, description));
}
