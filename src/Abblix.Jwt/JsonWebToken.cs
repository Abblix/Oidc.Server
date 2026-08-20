// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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

	/// <summary>
	/// Splits the token into its header and payload components, enabling pattern-style
	/// destructuring at the call site.
	/// </summary>
	/// <param name="header">Receives the JWS/JWT header section.</param>
	/// <param name="payload">Receives the claim-bearing payload section.</param>
	public void Deconstruct(out JsonWebTokenHeader header, out JsonWebTokenPayload payload)
	{
		header = Header;
		payload = Payload;
	}
}
