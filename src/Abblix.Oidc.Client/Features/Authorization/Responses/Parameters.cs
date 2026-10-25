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

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// The parameter names an authorization response carries back.
/// </summary>
/// <remarks>
/// Named to match the request side of the same feature and the server's own class, so the pair reads
/// as one protocol rather than two. The namespace is what tells the two apart; a different type stem
/// would send the next reader looking for a difference that is not there.
/// </remarks>
public static class Parameters
{
    /// <summary>
    /// The authorization code (RFC 6749 section 4.1.2).
    /// </summary>
    public const string Code = "code";

    /// <summary>
    /// The opaque value the client sent on the request and gets back unchanged (RFC 6749 section 4.1.2).
    /// </summary>
    public const string State = "state";

    /// <summary>
    /// An ID Token returned from the authorization endpoint, in the implicit and hybrid flows
    /// (OIDC Core 1.0 sections 3.2.2.5 and 3.3.2.5).
    /// </summary>
    public const string IdToken = "id_token";

    /// <summary>
    /// An access token returned from the authorization endpoint (RFC 6749 section 4.2.2).
    /// </summary>
    public const string AccessToken = "access_token";

    /// <summary>
    /// The type of the access token, which RFC 6749 section 4.2.2 makes REQUIRED whenever one is
    /// returned here.
    /// </summary>
    public const string TokenType = "token_type";

    /// <summary>
    /// How long the access token remains valid, in seconds (RFC 6749 section 4.2.2).
    /// </summary>
    public const string ExpiresIn = "expires_in";

    /// <summary>
    /// The scope actually granted, present when it differs from the one requested
    /// (RFC 6749 section 4.2.2).
    /// </summary>
    public const string Scope = "scope";

    /// <summary>
    /// The error code on a failed response (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string Error = "error";

    /// <summary>
    /// Human-readable elaboration on <see cref="Error"/> (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string ErrorDescription = "error_description";

    /// <summary>
    /// A page describing the error (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string ErrorUri = "error_uri";

    /// <summary>
    /// The issuer identifier of the authorization server that produced the response (RFC 9207 section 2).
    /// </summary>
    public const string Issuer = "iss";

    /// <summary>
    /// The end-user's login state at the provider, for a client watching the session.
    /// </summary>
    public const string SessionState = "session_state";
}
