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
        payload.Audiences = context.Resources is { Length: > 0 }
            ? Array.ConvertAll(context.Resources, res => res.OriginalString)
            : new[] { context.ClientId };
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
        var resources =
            payload.Audiences.Count() == 1 && payload.Audiences.Single() == payload.ClientId
                ? null
                : payload.Audiences
            .Select(aud => Uri.TryCreate(aud, UriKind.Absolute, out var uri) ? uri : null)
            .OfType<Uri>()
            .ToArray();

        return new AuthorizationContext(
            payload.ClientId.NotNull(nameof(payload.ClientId)),
            payload.Scope.NotNull(nameof(payload.Scope)).ToArray(),
            payload[JwtClaimTypes.RequestedClaims].Deserialize<RequestedClaims>(JsonSerializerOptions))
        {
            Nonce = payload.Nonce,
            Resources = resources,
        };
    }
}
