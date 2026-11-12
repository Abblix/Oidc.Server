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
/// The response modes a request can ask the provider to return the response by, as they appear on the
/// wire (OAuth 2.0 Multiple Response Type Encoding Practices).
/// </summary>
/// <remarks>
/// Named to match <c>Abblix.Oidc.Server.Common.Constants.ResponseModes</c>. The JARM variants the server
/// also defines are out of scope for this client.
/// </remarks>
public static class ResponseModes
{
    /// <summary>
    /// The response is appended to the redirect address as a query string. The default for the code flow
    /// (Multiple Response Type Encoding Practices section 5), and the mode a server-side callback reads.
    /// </summary>
    public const string Query = "query";

    /// <summary>
    /// The response is appended as a URL fragment. The default for any token-returning flow, and the one a
    /// server-side client cannot use: a fragment "is dereferenced solely by the user agent" (RFC 3986
    /// section 3.5) and never reaches the server. Only a browser-based client that reads the fragment
    /// itself can use this mode.
    /// </summary>
    public const string Fragment = "fragment";

    /// <summary>
    /// The provider returns an HTML page that POSTs the parameters back to the redirect address as a form
    /// (OAuth 2.0 Form Post Response Mode). This is how a server-side client receives a token-returning
    /// response, since the parameters arrive in a request body the server can read rather than in a
    /// fragment it cannot.
    /// </summary>
    public const string FormPost = "form_post";
}
