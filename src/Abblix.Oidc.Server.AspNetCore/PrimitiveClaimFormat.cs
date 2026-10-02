// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// One primitive JSON kind as a claim carries it: the value type marking it, and both directions of the conversion,
/// held together so a kind the write side tags is always one the read side recognizes.
/// </summary>
/// <param name="ValueType">The claim value type the kind is tagged with.</param>
/// <param name="Write">The claim text of a JSON value of this kind, or null when the value is of another kind.</param>
/// <param name="Read">The JSON value the claim text stands for, or null when the text does not parse as this kind.
/// </param>
internal sealed record PrimitiveClaimFormat(
	string ValueType,
	Func<JsonValue, string?> Write,
	Func<string, JsonNode?> Read);
