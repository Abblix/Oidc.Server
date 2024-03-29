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

using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder that converts a space-separated string into an array of strings.
/// </summary>
/// <remarks>
/// This binder is useful for processing query parameters or other data represented as a single string
/// with values separated by spaces. It splits the input string by spaces and converts the result into an array.
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
