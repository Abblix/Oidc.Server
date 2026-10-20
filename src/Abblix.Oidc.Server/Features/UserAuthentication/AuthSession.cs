// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Features.Storages;

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
    /// When the session was last signed in through <see cref="IAuthSessionService.SignInAsync"/>: on authentication,
    /// or when the end user picked it among their sessions. A session signed in after the server sent the end user to
    /// choose an account is the one <c>prompt=select_account</c> asked for, so a host signing a session in again for any
    /// other reason while that page is open answers it too. Null for a session the host never signed in that way.
    /// </summary>
    public DateTimeOffset? SignedInAt { get; init; }

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
    /// A list of authentication methods used during the user's authentication process,
    /// represented as Authentication Method Reference (AMR) values according to the OpenID Connect specification.
    /// These values indicate how the user was authenticated, such as using a password, multifactor authentication,
    /// biometric verification, or other supported mechanisms. This information is useful for auditing,
    /// enforcing authentication policies, or satisfying specific security requirements.
    /// </summary>
    public ICollection<string>? AuthenticationMethodReferences { get; init; }

    /// <summary>
    /// The email address used for authentication, such as the one an external provider (Google, Microsoft) or a
    /// challenge confirmed, kept exactly as used whatever other addresses the account holds.
    /// </summary>
    /// <remarks>
    /// An access token carries it only when the user-information endpoint would ask the host's provider for it,
    /// since every resource server that token reaches reads it. The server does not put it in an ID token itself; the user-information provider
    /// receives the session and decides which address it releases, in the ID token and at the user-information
    /// endpoint alike.
    /// </remarks>
    public string? Email { get; init; }

    /// <summary>
    /// Whether <see cref="Email"/> has been verified, by an external provider that verifies addresses or by a
    /// challenge the user completed.
    /// </summary>
    /// <remarks>
    /// An access token carries it exactly when it carries <see cref="Email"/>.
    /// </remarks>
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

    /// <summary>
    /// How long the user agent keeps the session. On a sign-in, what the host chose, with
    /// <see cref="SessionPersistence.Unstated"/> keeping what the end user's current session has; on a session read
    /// back, what it was written with.
    /// </summary>
    /// <remarks>
    /// A session service with no notion of persistence may ignore it. It belongs to the user agent's copy of the
    /// session, so a grant stored with the session does not keep it, and reads it back as unstated.
    /// </remarks>
    [JsonIgnore]
    [NotStored("Kept by the authentication cookie, which is where the session lives")]
    public SessionPersistence Persistence { get; init; } = SessionPersistence.Unstated;
}
