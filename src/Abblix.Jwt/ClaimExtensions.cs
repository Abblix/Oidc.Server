// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
