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
	/// <returns>True if the flag is found; otherwise, false.</returns>
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
			var allowedValue = allowedValues.FirstOrDefault(value => string.Equals(value, sourceValue, StringComparison.OrdinalIgnoreCase));
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
