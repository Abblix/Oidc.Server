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
using System.Security.Claims;
using System.Text.Json;

namespace Abblix.Oidc.Server.Mvc;

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
			values = JsonSerializer.Deserialize<List<string>>(claimValue);
			return values != null;
		}

		values = new List<string> { claimValue };
		return true;
	}
}
