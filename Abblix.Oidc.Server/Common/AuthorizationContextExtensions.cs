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

using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Provides extension methods for working with <see cref="AuthorizationContext"/> objects,
/// facilitating the conversion between authorization contexts and JWT claims.
/// </summary>
public static class AuthorizationContextExtensions
{
    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Applies the information from an <see cref="AuthorizationContext"/> to a <see cref="JsonWebTokenPayload"/>,
    /// converting the context into JWT claims.
    /// </summary>
    /// <param name="context">The <see cref="AuthorizationContext"/> containing authorization details.</param>
    /// <param name="payload">The JWT payload where the authorization context information will be applied as claims.</param>
    /// <remarks>
    /// This method is useful for embedding authorization details directly into a JWT, allowing for efficient transfer
    /// and validation of authorization information.
    /// </remarks>
    public static void ApplyTo(this AuthorizationContext context, JsonWebTokenPayload payload)
    {
        payload.ClientId = context.ClientId;
        payload.Scope = context.Scope;
        payload.Nonce = context.Nonce;
        payload[JwtClaimTypes.RequestedClaims] = JsonSerializer.SerializeToNode(context.RequestedClaims, JsonSerializerOptions);
    }

    /// <summary>
    /// Creates an <see cref="AuthorizationContext"/> from a <see cref="JsonWebTokenPayload"/>,
    /// converting JWT claims back into an authorization context.
    /// </summary>
    /// <param name="payload">The JWT payload containing claims that represent an authorization context.</param>
    /// <returns>An instance of <see cref="AuthorizationContext"/> populated with information derived from
    /// the JWT claims.</returns>
    /// <remarks>
    /// This method facilitates the extraction of authorization details from JWT claims,
    /// reconstructing an <see cref="AuthorizationContext"/> for further processing or validation.
    /// </remarks>
    public static AuthorizationContext ToAuthorizationContext(this JsonWebTokenPayload payload)
    {
        return new AuthorizationContext(
            payload.ClientId.NotNull(nameof(payload.ClientId)),
            payload.Scope.NotNull(nameof(payload.Scope)).ToArray(),
            payload[JwtClaimTypes.RequestedClaims].Deserialize<RequestedClaims>(JsonSerializerOptions));
    }
}
