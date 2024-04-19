// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
}
