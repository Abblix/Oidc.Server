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


namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Represents a successful introspection response, indicating whether the token is active and providing its claims.
/// </summary>
/// <remarks>
/// Specific implementations may extend this structure with their own service-specific response names as
/// top-level members of this JSON object. Response names intended for use across domains must be registered
/// in the "OAuth Token Introspection Response" registry as defined in Section 3.1.
/// </remarks>
public record IntrospectionSuccessResponse(bool Active, JsonObject? Claims) : IntrospectionResponse
{
    /// <summary>
    /// Gets or sets whether the token is active.
    /// </summary>
    public bool Active { get; } = Active;

    /// <summary>
    /// Gets or sets the claims associated with the token.
    /// </summary>
    public JsonObject? Claims { get; } = Claims;
}
