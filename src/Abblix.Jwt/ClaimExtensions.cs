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
/// Provides extension methods for handling claims, particularly for converting between JWT claims and security claims.
/// </summary>
public static class ClaimExtensions
{
	/// <summary>
	/// Converts a <see cref="JsonNode"/> to a string representation. If the node is a <see cref="JsonValue"/>,
	/// the value is extracted as a string; otherwise, the JSON string representation of the node is returned.
	/// </summary>
	/// <param name="node">The <see cref="JsonNode"/> to convert to a string.</param>
	/// <returns>A string representation of the <see cref="JsonNode"/>.</returns>
	public static string AsString(this JsonNode node) => node switch
	{
		JsonValue value when value.TryGetValue(out string? s) => s,
		_ => node.ToJsonString(),
	};
}
