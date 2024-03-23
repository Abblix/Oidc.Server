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
