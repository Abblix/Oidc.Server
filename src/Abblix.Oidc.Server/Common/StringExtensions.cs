// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

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
	public static bool TryParse(
		this string source,
		string[] allowedValues,
		char separator,
		[NotNullWhen(true)] out string[]? values)
	{
		if (string.IsNullOrEmpty(source))
		{
			values = [];
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
				values = null;
				return false;
			}

			result.Add(allowedValue);
		}

		values = result.ToArray();
		return true;
	}
}
