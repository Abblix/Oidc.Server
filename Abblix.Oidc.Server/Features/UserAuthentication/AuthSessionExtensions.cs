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

using Abblix.Jwt;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// Provides extension methods for <see cref="AuthSession"/>, facilitating the conversion
/// between authentication session information and JWT claims.
/// </summary>
public static class AuthSessionExtensions
{
    /// <summary>
    /// Applies the values from an <see cref="AuthSession"/> object to a <see cref="JsonWebTokenPayload"/>,
    /// effectively transferring the authentication session information into JWT claims.
    /// </summary>
    /// <param name="authSession">The authentication session containing the user's authentication information.</param>
    /// <param name="payload">The JWT payload where the authentication session information will be applied as claims.</param>
    /// <remarks>
    /// This method is useful for including specific authentication session details, such as the subject,
    /// authentication time, and session ID, into the JWT for subsequent validation or processing.
    /// </remarks>
    public static void ApplyTo(this AuthSession authSession, JsonWebTokenPayload payload)
    {
        payload.Subject = authSession.Subject;
        payload.IdentityProvider = authSession.IdentityProvider;
        payload.SessionId = authSession.SessionId;
        payload.AuthenticationTime = authSession.AuthenticationTime;
    }

    /// <summary>
    /// Creates an <see cref="AuthSession"/> object from a collection of JWT claims present in a <see cref="JsonWebTokenPayload"/>.
    /// </summary>
    /// <param name="payload">The JWT payload containing claims that represent an authentication session.</param>
    /// <returns>An instance of <see cref="AuthSession"/> populated with information derived from the JWT claims.</returns>
    /// <remarks>
    /// This method allows for the reconstruction of an authentication session from the claims encoded in a JWT.
    /// It is particularly useful when processing JWTs to extract authentication and user session details.
    /// </remarks>
    public static AuthSession ToAuthSession(this JsonWebTokenPayload payload) => new(
        payload.Subject.NotNull(nameof(payload.Subject)),
        payload.SessionId.NotNull(nameof(payload.SessionId)),
        payload.AuthenticationTime.NotNull(nameof(payload.AuthenticationTime)),
        payload.IdentityProvider.NotNull(nameof(payload.IdentityProvider)));
}
