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
