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
/// Thrown when an authorization response must not be acted on. The login it belongs to stops here.
/// </summary>
/// <remarks>
/// RFC 9207 section 2.4 states the consequence for the issuer case in full: a client that finds the
/// wrong issuer "MUST reject the authorization response and MUST NOT proceed with the authorization
/// grant". Throwing is how that second half is made unskippable - there is no result object a caller
/// can look past on the way to redeeming the code.
/// </remarks>
public sealed class AuthorizationResponseException : Exception
{
    /// <summary>
    /// Creates the exception for a response this client refused: a wrong issuer, a shape no
    /// specification defines, a parameter that arrived twice.
    /// </summary>
    public AuthorizationResponseException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Creates the exception for a response in which the provider itself refused, carrying the code it
    /// returned so a caller can act on it.
    /// </summary>
    /// <remarks>
    /// This overload is used only once the issuer has been confirmed. Before that, per RFC 9207
    /// section 2.4 - "For error responses, clients MUST NOT assume that the error originates from the
    /// intended authorization server" - the code is an unverified string and must not be presented as
    /// the provider's answer.
    /// </remarks>
    public AuthorizationResponseException(string message, string error, string? errorDescription)
        : base(message)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    /// <summary>
    /// The error code the provider returned, or <see langword="null"/> when this client refused the
    /// response for its own reasons rather than relaying the provider's.
    /// </summary>
    /// <remarks>
    /// Carried apart from the message because a caller acts on it: <c>access_denied</c> is a user who
    /// pressed Cancel and deserves a different answer from <c>server_error</c>. One of
    /// <see cref="AuthorizationErrorCodes"/>, or a value from an extension this client does not know.
    /// </remarks>
    public string? Error { get; }

    /// <summary>
    /// The provider's human-readable elaboration on <see cref="Error"/>, when it gave one.
    /// </summary>
    /// <remarks>
    /// Text the provider chose. Bounded in character set by RFC 6749 section 4.1.2.1 but not in
    /// meaning, so treat it as untrusted: a log entry naming its source, never a page rendered to the
    /// user and never markup.
    /// </remarks>
    public string? ErrorDescription { get; }
}
