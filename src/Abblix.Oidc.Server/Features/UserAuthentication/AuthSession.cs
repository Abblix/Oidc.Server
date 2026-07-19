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

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// Represents a model of an authentication session for a logged-in user, capturing essential details about the user's
/// authentication state and interactions within the system.
/// </summary>
public record AuthSession(string Subject, string SessionId, DateTimeOffset AuthenticationTime, string IdentityProvider)
{
    /// <summary>
    /// The unique identifier for the user in the session. This is typically a user-specific identifier that can be
    /// used to retrieve user details or verify the user's identity across different parts of the application.
    /// </summary>
    public string Subject { get; init; } = Subject;

    /// <summary>
    /// The unique identifier of the session, used to track the session across requests and possibly across
    /// different services.
    /// </summary>
    public string SessionId { get; init; } = SessionId;

    /// <summary>
    /// The timestamp indicating when the user was authenticated. This is used for session management purposes such as
    /// session expiration and activity logging.
    /// </summary>
    public DateTimeOffset AuthenticationTime { get; init; } = AuthenticationTime;

    /// <summary>
    /// The provider used to authenticate the user's identity. This could be a local database, an external identity
    /// provider, or a social login provider, and can be useful for auditing and enforcing security policies based
    /// on the origin of authentication.
    /// </summary>
    public string? IdentityProvider { get; init; } = IdentityProvider;

    /// <summary>
    /// Indicates the authentication context class that the authentication performed satisfied, according to
    /// specifications such as SAML 2.0 or OpenID Connect. This may dictate the level of assurance provided
    /// by the authentication process.
    /// </summary>
    public string? AuthContextClassRef { get; init; }

    /// <summary>
    /// A collection of client identifiers that the user has interacted with during the session.
    /// This can be used to manage and track user consent and interaction with multiple clients within the same session.
    /// </summary>
    public ICollection<string> AffectedClientIds { get; init; } = new List<string>();

    /// <summary>
    /// A list of authentication methods used during the user's authentication process,
    /// represented as Authentication Method Reference (AMR) values according to the OpenID Connect specification.
    /// These values indicate how the user was authenticated, such as using a password, multifactor authentication,
    /// biometric verification, or other supported mechanisms. This information is useful for auditing,
    /// enforcing authentication policies, or satisfying specific security requirements.
    /// </summary>
    public ICollection<string>? AuthenticationMethodReferences { get; init; }

    /// <summary>
    /// The email address used for authentication. When specified, this exact email is included in the authentication
    /// cookie and ID token claims, regardless of other emails associated with the user account.
    /// This ensures external provider emails (Google, Microsoft) or challenge emails are preserved exactly as used.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Indicates whether the email address has been verified. When true, the email_verified claim is set to true
    /// in ID tokens. This is particularly useful for external providers that verify emails or when email verification
    /// has been completed through challenge flows.
    /// </summary>
    public bool? EmailVerified { get; init; }

    /// <summary>
    /// Additional custom claims to include in the authentication session.
    /// These claims will be serialized to the authentication cookie and can be included in tokens.
    /// Supports any JSON value: strings, numbers, booleans, arrays, objects.
    /// </summary>
    /// <example>
    /// <code>
    /// AdditionalClaims = new JsonObject
    /// {
    ///     ["tenant_id"] = "tenant-123",                          // string
    ///     ["roles"] = new JsonArray("admin", "user"),            // array
    ///     ["permissions"] = new JsonArray("read", "write"),      // array
    ///     ["is_verified"] = true,                                // boolean
    ///     ["login_count"] = 42,                                  // number
    ///     ["metadata"] = new JsonObject                          // nested object
    ///     {
    ///         ["department"] = "Engineering",
    ///         ["manager"] = "john@example.com"
    ///     }
    /// }
    /// </code>
    /// </example>
    public JsonObject? AdditionalClaims { get; init; }
}
