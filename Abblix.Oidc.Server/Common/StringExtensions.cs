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

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Handy extensions for <see cref="string">strings</see>.
/// </summary>
internal static class StringExtensions
{
	/// <summary>
	/// Checks if the array of strings contains a specified flag.
	/// </summary>
	/// <param name="values">The array of strings to check.</param>
	/// <param name="flag">The flag to search for.</param>
	/// <returns>True, if the flag is found, otherwise, false.</returns>
	public static bool HasFlag(this string[]? values, string flag)
		=> values != null && values.Contains(flag, StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Attempts to parse a string into an array of allowed values using a separator.
	/// </summary>
	/// <param name="source">The source string to parse.</param>
	/// <param name="allowedValues">The array of allowed values.</param>
	/// <param name="separator">The character separator.</param>
	/// <param name="values">The parsed values if successful; otherwise, null.</param>
	/// <returns>True if parsing is successful; otherwise, false.</returns>
	public static bool TryParse(this string source, string[] allowedValues, char separator, out string[] values)
	{
		if (string.IsNullOrEmpty(source))
		{
			values = Array.Empty<string>();
			return true;
		}

		var sourceValues = source.Split(separator, StringSplitOptions.RemoveEmptyEntries);
		var result = new List<string>(sourceValues.Length);
		foreach (var sourceValue in sourceValues)
		{
			var allowedValue = allowedValues.FirstOrDefault(
				value => string.Equals(value, sourceValue, StringComparison.OrdinalIgnoreCase));
			if (allowedValue == null)
			{
				values = default!;
				return false;
			}

			result.Add(allowedValue);
		}

		values = result.ToArray();
		return true;
	}
}
