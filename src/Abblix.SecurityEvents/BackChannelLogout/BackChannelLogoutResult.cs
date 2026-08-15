// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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

    /// <summary>
    /// The header Section 2.8 asks the response to carry: "The RP's response SHOULD include the
    /// Cache-Control HTTP response header field with a no-store value, keeping the response from
    /// being cached to prevent cached responses from interfering with future logout requests."
    /// </summary>
    /// <remarks>
    /// Stated here rather than left to each adapter, because it applies to both answers and an
    /// adapter that sets it on one of them is the likelier mistake.
    /// </remarks>
    public const string CacheControl = "no-store";
}
