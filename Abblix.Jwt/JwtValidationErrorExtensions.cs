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

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Provides extension methods for <see cref="JwtValidationError"/>.
/// </summary>
public static class JwtValidationErrorExtensions
{
	/// <summary>
	/// Gets a user-friendly description of the JWT validation error with proper sentence capitalization.
	/// </summary>
	/// <param name="error">The JWT validation error.</param>
	/// <param name="lowercaseFirst">
	/// If true, converts the first letter to lowercase for embedding in larger sentences.
	/// If false, preserves the original capitalization. Default is true.
	/// </param>
	/// <returns>
	/// The error description, optionally with the first letter in lowercase if a description is available,
	/// otherwise returns the error code as a string.
	/// </returns>
	/// <remarks>
	/// This method is useful for embedding error descriptions in the middle of sentences,
	/// where starting with a lowercase letter maintains proper grammar.
	/// Example with lowercaseFirst=true: "The id token hint contains invalid token: token has expired"
	/// Example with lowercaseFirst=false: "Token has expired"
	/// </remarks>
	public static string ToDescription(this JwtValidationError error, bool lowercaseFirst = true)
	{
		if (!error.ErrorDescription.HasValue())
			return error.Error.ToString();

		if (!lowercaseFirst)
			return error.ErrorDescription;

		return char.ToLowerInvariant(error.ErrorDescription[0]) + error.ErrorDescription[1..];
	}
}
