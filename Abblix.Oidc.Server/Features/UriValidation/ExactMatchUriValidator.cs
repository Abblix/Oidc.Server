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

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Validates a URI based on an exact match against a predefined value, disregarding the query and fragment parts.
/// </summary>
public sealed class ExactMatchUriValidator(Uri validUri, bool ignoreQueryAndFragment = false) : IUriValidator
{
	private readonly Uri _validUri = !validUri.IsAbsoluteUri
		? throw new ArgumentException($"{nameof(validUri)} must be absolute")
		: validUri;

	/// <summary>
	/// Validates the specified URI by checking for an exact match with the predefined URI.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	/// <returns><c>true</c> if the specified URI exactly matches the predefined URI, otherwise <c>false</c>.</returns>
	public bool IsValid(Uri uri)
	{
		if (ignoreQueryAndFragment && (uri.Query.HasValue() || uri.Fragment.HasValue()))
		{
			uri = new System.UriBuilder(uri) { Query = null, Fragment = null }.Uri;
		}

		return _validUri == uri;
	}
}
