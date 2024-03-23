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

namespace Abblix.Jwt;

/// <summary>
/// Represents a JSON Web Token (JWT), a compact, URL-safe means of representing
/// claims to be transferred between two parties. This record encapsulates the standard
/// JWT structure, offering properties to access and manipulate the header, payload, and claims.
/// </summary>
public record JsonWebToken
{
	/// <summary>
	/// Represents the JWT header, containing metadata about the type of token and the algorithms used to secure it.
	/// </summary>
	/// <remarks>
	/// The header typically includes information such as the type of token (JWT) and
	/// the signing algorithm (e.g., HS256, RS256). This property allows direct access
	/// and manipulation of these values.
	/// </remarks>
	public JsonWebTokenHeader Header { get; init; } = new(new JsonObject());

	/// <summary>
	/// Represents the JWT payload, containing the claims about the entity (typically, the user)
	/// and additional metadata.
	/// </summary>
	/// <remarks>
	/// The payload is where the claims of the JWT are stored. This includes standard claims such as
	/// issuer, subject, and expiration time, as well as custom claims as required by the application.
	/// </remarks>
	public JsonWebTokenPayload Payload { get; init; } = new(new JsonObject());
}
