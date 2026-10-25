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
/// The error codes an authorization response can carry.
/// </summary>
/// <remarks>
/// Kept apart from <see cref="Tokens.TokenErrorCodes"/> and
/// <see cref="ProtectedResources.ResourceErrorCodes"/>, and not because the sets are disjoint - the RFCs
/// define some of the same strings for more than one endpoint. It is that each endpoint answers with its
/// own vocabulary, so a caller reading an authorization response is never offered <c>invalid_grant</c>, and
/// one reading a token response is never offered <c>login_required</c>. A single merged set would suggest
/// codes can arrive where they cannot.
/// The three carry the responder in their names rather than relying on the namespace, because that is how
/// they are read: from outside, by a host comparing the code on a caught exception, where three types
/// called ErrorCodes would offer each other's completions.
/// The list is open. RFC 9396 adds <c>invalid_authorization_details</c> at this endpoint, extensions
/// register more, and an unfamiliar code is exactly the one an operator needs to see verbatim - which
/// is why the wire value stays a string throughout rather than becoming an enum with an
/// everything-else member.
/// </remarks>
public static class AuthorizationErrorCodes
{
    /// <summary>
    /// The request was malformed: a parameter missing, repeated, or otherwise invalid
    /// (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>
    /// This client is not allowed to request an authorization code this way (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>
    /// The user or the provider refused the request (RFC 6749 section 4.1.2.1).
    /// </summary>
    /// <remarks>
    /// The one code that is a normal outcome rather than a fault: it is what a user pressing Cancel
    /// produces. Worth distinguishing when deciding what to show them.
    /// </remarks>
    public const string AccessDenied = "access_denied";

    /// <summary>
    /// The provider does not support obtaining a code by this response type (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string UnsupportedResponseType = "unsupported_response_type";

    /// <summary>
    /// The requested scope is invalid, unknown, or malformed (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>
    /// The provider met an unexpected condition (RFC 6749 section 4.1.2.1).
    /// </summary>
    /// <remarks>
    /// It exists because the provider cannot answer a redirect-based request with a 500: the response
    /// has to come back through the browser to be readable at all.
    /// </remarks>
    public const string ServerError = "server_error";

    /// <summary>
    /// The provider is temporarily overloaded or down (RFC 6749 section 4.1.2.1).
    /// </summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";

    /// <summary>
    /// The request needs user interaction that <c>prompt=none</c> forbade
    /// (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string InteractionRequired = "interaction_required";

    /// <summary>
    /// Authentication is needed and <c>prompt=none</c> forbade asking for it
    /// (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string LoginRequired = "login_required";

    /// <summary>
    /// The user must choose a session and <c>prompt=none</c> forbade asking
    /// (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string AccountSelectionRequired = "account_selection_required";

    /// <summary>
    /// Consent is needed and <c>prompt=none</c> forbade asking for it
    /// (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string ConsentRequired = "consent_required";

    /// <summary>
    /// The <c>request_uri</c> is invalid or unreachable (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string InvalidRequestUri = "invalid_request_uri";

    /// <summary>
    /// The request object is invalid (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string InvalidRequestObject = "invalid_request_object";

    /// <summary>
    /// The provider does not support the <c>request</c> parameter
    /// (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string RequestNotSupported = "request_not_supported";

    /// <summary>
    /// The provider does not support the <c>request_uri</c> parameter
    /// (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string RequestUriNotSupported = "request_uri_not_supported";

    /// <summary>
    /// The provider does not support registration through the <c>registration</c> parameter
    /// (OpenID Connect Core 1.0 section 3.1.2.6).
    /// </summary>
    public const string RegistrationNotSupported = "registration_not_supported";
}
