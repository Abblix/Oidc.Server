// Abblix OIDC Client Library
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


namespace Abblix.Oidc.Client.Features.Authorization.Requests;

/// <summary>
/// The response type ATOMS a request combines, as they appear on the wire. A response_type value is one
/// or more of these joined by spaces (RFC 6749 section 3.1.1, and the multi-valued combinations OAuth 2.0
/// Multiple Response Type Encoding Practices registers).
/// </summary>
/// <remarks>
/// Named to match <c>Abblix.Oidc.Server.Common.Constants.ResponseTypes</c>, so the same wire value reads
/// as the same concept on both sides of the family.
/// </remarks>
public static class ResponseTypes
{
    /// <summary>
    /// The authorization code. The safe default: it comes back through the browser but is redeemed over a
    /// back channel with PKCE, so nothing usable rides in the browser's address bar.
    /// </summary>
    public const string Code = "code";

    /// <summary>
    /// An access token returned from the authorization endpoint. A front-channel token, discouraged, and
    /// only sent when the host opts into a token-returning flow.
    /// </summary>
    public const string Token = "token";

    /// <summary>
    /// An ID Token returned from the authorization endpoint. Bound to the request by its nonce, and to any
    /// code or access token beside it by <c>c_hash</c> / <c>at_hash</c> (OIDC Core 1.0 section 3.3.2.11).
    /// </summary>
    public const string IdToken = "id_token";
}
