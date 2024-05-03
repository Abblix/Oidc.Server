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
