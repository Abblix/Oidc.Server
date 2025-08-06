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
        payload.AuthenticationMethodReferences = authSession.AuthenticationMethodReferences;
        payload.AuthContextClassRef = authSession.AuthContextClassRef;
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
    public static AuthSession ToAuthSession(this JsonWebTokenPayload payload)
    {
        var authSession = new AuthSession(
            payload.Subject.NotNull(nameof(payload.Subject)),
            payload.SessionId.NotNull(nameof(payload.SessionId)),
            payload.AuthenticationTime.NotNull(nameof(payload.AuthenticationTime)),
            payload.IdentityProvider.NotNull(nameof(payload.IdentityProvider)))
            {
                AuthContextClassRef = payload.AuthContextClassRef,
                AuthenticationMethodReferences = payload.AuthenticationMethodReferences?.ToList(),
            };

        return authSession;
    }
}
