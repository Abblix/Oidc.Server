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

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// How an RP tells a provider that a logout request was bad: the optional body of the 400 response
/// (OpenID Connect Back-Channel Logout 1.0 Section 2.8).
/// </summary>
/// <remarks>
/// The same shape as a push delivery's error and deliberately not the same type. Section 2.8 sends
/// the reader to "Section 5.2 of OAuth 2.0" for these parameters, so they travel as <c>error</c>
/// and <c>error_description</c>, where a SET delivery's travel as <c>err</c> and
/// <c>description</c> (RFC 8935 Section 2.3). One record serving both would put one vocabulary's
/// names on the other's wire.
/// <para>
/// Section 2.8 also says what the body is for and what it is not for: "the information conveyed in
/// the response body is intended to help debug deployments; it is not intended that
/// implementations use different error values to trigger different runtime behaviors." So the
/// description is where the detail belongs, and the code stays coarse.
/// </para>
/// </remarks>
/// <param name="Error">The error code. Section 2.8 names only <c>invalid_request</c>.</param>
/// <param name="Description">
/// A human-readable account of what failed - the half an operator on the provider's side reads.
/// Optional by Section 2.8, always supplied here, since a code this coarse says almost nothing on
/// its own.</param>
public sealed record BackChannelLogoutError(
    [property: JsonPropertyName(BackChannelLogoutError.ParameterNames.Error)] string Error,
    [property: JsonPropertyName(BackChannelLogoutError.ParameterNames.Description)] string Description)
{
    /// <summary>
    /// The wire names of the error members (RFC 6749 Section 5.2, by the reference in
    /// OpenID Connect Back-Channel Logout 1.0 Section 2.8).
    /// </summary>
    public static class ParameterNames
    {
        /// <summary>The error code member.</summary>
        public const string Error = "error";

        /// <summary>The human-readable description member.</summary>
        public const string Description = "error_description";
    }

    /// <summary>
    /// The one code the specification names: "An error value of <c>invalid_request</c> MAY be used
    /// to indicate that there was a problem with the syntax of the logout request."
    /// </summary>
    public const string InvalidRequest = "invalid_request";
}
