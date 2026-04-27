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

using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Binds a single space-separated request value into a string array.
/// Mirrors the wire format used by OAuth 2.0 / OpenID Connect for parameters such as
/// <c>scope</c>, <c>response_type</c>, <c>prompt</c>, <c>acr_values</c>, and <c>ui_locales</c>
/// (RFC 6749 § 3.3 and OIDC Core 1.0 § 3.1.2.1).
/// </summary>
/// <remarks>
/// Tokens are split on the ASCII space character; consecutive spaces produce no empty entries.
/// Other whitespace (tab, newline) is preserved as part of a token, matching the literal
/// SP delimiter required by the specifications.
/// </remarks>
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
