// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Text.Json;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Extension methods for <see cref="ClaimsPrincipal"/>.
/// </summary>
public static class ClaimsPrincipalExtensions
{
	/// <summary>
	/// Attempts to retrieve a list of strings from a claim value.
	/// The claim value can be either a JSON-serialized array or a plain string value.
	/// </summary>
	public static bool TryGetStringList(
		this ClaimsPrincipal principal,
		string claimType,
		[NotNullWhen(true)] out List<string>? values)
	{
		var claimValue = principal.FindFirstValue(claimType);
		if (claimValue == null)
		{
			values = null;
			return false;
		}

		if (claimValue.StartsWith('['))
		{
			try
			{
				values = JsonSerializer.Deserialize<List<string>>(claimValue);
			}
			catch (JsonException)
			{
				// A claim that opens like a JSON array but is malformed is treated as absent, not a 500.
				values = null;
				return false;
			}

			return values != null;
		}

		values = [claimValue];
		return true;
	}
}
