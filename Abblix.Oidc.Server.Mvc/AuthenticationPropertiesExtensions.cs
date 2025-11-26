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

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

namespace Abblix.Oidc.Server.Mvc;

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
			values = JsonSerializer.Deserialize<List<string>>(json);
			if (values != null)
				return true;
		}

		values = null;
		return false;
	}
}
