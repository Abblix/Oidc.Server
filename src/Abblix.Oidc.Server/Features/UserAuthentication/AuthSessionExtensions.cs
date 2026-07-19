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

using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
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
    /// Standard JWT and OIDC claims that are handled as dedicated properties on <see cref="AuthSession"/>.
    /// These claims are excluded when extracting additional claims from JWT payloads to prevent duplication.
    /// </summary>
    private static readonly HashSet<string> StandardClaims = new(StringComparer.Ordinal)
    {
        JwtClaimTypes.Subject,
        JwtClaimTypes.SessionId,
        JwtClaimTypes.AuthenticationTime,
        JwtClaimTypes.AuthenticationMethodReferences,
        JwtClaimTypes.AuthContextClassRef,
        JwtClaimTypes.IdentityProvider,
        JwtClaimTypes.Email,
        JwtClaimTypes.EmailVerified,
        JwtClaimTypes.Issuer,
        JwtClaimTypes.Audience,
        JwtClaimTypes.ExpiresAt,
        JwtClaimTypes.IssuedAt,
        JwtClaimTypes.NotBefore,
        JwtClaimTypes.JwtId,
        JwtClaimTypes.Scope,
        JwtClaimTypes.ClientId,
    };

    /// <summary>
    /// Applies the values from an <see cref="AuthSession"/> object to a <see cref="JsonWebTokenPayload"/>,
    /// effectively transferring the authentication session information into JWT claims.
    /// </summary>
    /// <param name="authSession">The authentication session containing the user's authentication information.</param>
    /// <param name="payload">The JWT payload where the authentication session information will be applied as claims.</param>
    /// <remarks>
    /// This method transfers authentication session details into the JWT payload, including:
    /// - Subject, SessionId, AuthenticationTime, IdentityProvider, AuthContextClassRef, AuthenticationMethodReferences
    /// - Email and EmailVerified (when specified in the session)
    /// - Any additional custom claims from AdditionalClaims
    /// </remarks>
    public static void ApplyTo(this AuthSession authSession, JsonWebTokenPayload payload)
    {
        payload.Subject = authSession.Subject;
        payload.IdentityProvider = authSession.IdentityProvider;
        payload.SessionId = authSession.SessionId;
        payload.AuthenticationTime = authSession.AuthenticationTime;
        payload.AuthenticationMethodReferences = authSession.AuthenticationMethodReferences;
        payload.AuthContextClassRef = authSession.AuthContextClassRef;

        if (authSession.Email != null)
            payload.Email = authSession.Email;

        if (authSession.EmailVerified.HasValue)
            payload.EmailVerified = authSession.EmailVerified.Value;

        // Apply additional claims to payload
        if (authSession.AdditionalClaims != null)
        {
            foreach (var (claimType, jsonValue) in authSession.AdditionalClaims)
            {
                if (jsonValue != null)
                {
                    payload[claimType] = Clone(jsonValue);
                }
            }
        }
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
            Email = payload.Email,
            EmailVerified = payload.EmailVerified,
            AdditionalClaims = ExtractAdditionalClaims(payload),
        };

        return authSession;
    }

    /// <summary>
    /// Extracts additional claims from a JWT payload by excluding standard OIDC claims.
    /// </summary>
    /// <param name="payload">The JWT payload to extract claims from.</param>
    /// <returns>
    /// A <see cref="JsonObject"/> containing only non-standard claims with deep-cloned values,
    /// or null if no additional claims are present.
    /// </returns>
    /// <remarks>
    /// This method filters out standard claims defined in <see cref="StandardClaims"/> and creates
    /// deep clones of remaining claim values to prevent unintended modifications to the original payload.
    /// Uses lazy allocation - the JsonObject is only created when at least one additional claim is found.
    /// </remarks>
    private static JsonObject? ExtractAdditionalClaims(JsonWebTokenPayload payload)
    {
        JsonObject? additionalClaims = null;

        foreach (var (key, jsonNode) in payload.Json)
        {
            if (jsonNode is null || StandardClaims.Contains(key))
                continue;

            additionalClaims ??= new JsonObject();
            additionalClaims[key] = Clone(jsonNode);
        }

        return additionalClaims;
    }

    /// <summary>
    /// Creates a deep clone of a <see cref="JsonNode"/>.
    /// Uses <see cref="JsonNode.DeepClone"/> on .NET 8+ for better performance,
    /// falls back to serialization/deserialization on earlier frameworks.
    /// </summary>
    /// <param name="node">The JSON node to clone.</param>
    /// <returns>A deep clone of the input node.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static JsonNode Clone(JsonNode node)
    {
#if NET8_0_OR_GREATER
        return node.DeepClone();
#else
        return JsonNode.Parse(node.ToJsonString())!;
#endif
    }
}
