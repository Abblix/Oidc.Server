// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Oidc.Server.Mvc.Attributes;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Binds a single space-separated request value into a string array.
/// Mirrors the wire format used by OAuth 2.0 / OpenID Connect for parameters such as
/// <c>scope</c>, <c>response_type</c>, <c>prompt</c>, <c>acr_values</c>, and <c>ui_locales</c>
/// (RFC 6749 section 3.3 and OIDC Core 1.0 section 3.1.2.1).
/// </summary>
/// <remarks>
/// Tokens are split on the ASCII space character; consecutive spaces produce no empty entries.
/// Other whitespace (tab, newline) is preserved as part of a token, matching the literal
/// SP delimiter required by the specifications.
/// </remarks>
[Binds(typeof(SpaceSeparatedStringAttribute))]
public class SpaceSeparatedValuesBinder : ModelBinderBase
{
	/// <summary>
	/// Parses a space-separated string and converts it into an array of strings.
	/// </summary>
	/// <param name="type">The type of the model being bound, expected to be an array of strings.</param>
	/// <param name="values">The string values from the request, expected to be space-separated.</param>
	/// <param name="result">The parsed array of strings, if successful.</param>
	/// <returns>
	/// Always returns <c>true</c> as the method is designed to handle empty or null inputs gracefully.
	/// </returns>
	/// <remarks>
	/// The method splits the input string by spaces. Each separated segment is treated as an individual string in the resulting array.
	/// Empty entries are ignored, so strings with consecutive spaces won't result in empty strings in the array.
	/// </remarks>
	protected override bool TryParse(Type type, StringValues values, out object? result)
	{
		result = values
			.SelectMany(value => value?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
			                     ?? Enumerable.Empty<string>())
			.ToArray();

		return true;
	}
}
