// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Extension methods for <see cref="AuthenticationProperties"/>.
/// </summary>
public static class AuthenticationPropertiesExtensions
{
	/// <summary>
	/// Attempts to retrieve a list of strings from authentication properties.
	/// The value is expected to be a JSON-serialized array of strings.
	/// </summary>
	public static bool TryGetStringList(
		this AuthenticationProperties properties,
		string key,
		[NotNullWhen(true)] out List<string>? values)
	{
		var json = properties.GetString(key);
		if (json != null)
		{
			try
			{
				values = JsonSerializer.Deserialize<List<string>>(json);
			}
			catch (JsonException)
			{
				// A property tampered with or written by another component is treated as absent, not a 500.
				values = null;
				return false;
			}

			if (values != null)
				return true;
		}

		values = null;
		return false;
	}
}
