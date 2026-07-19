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
/// Implements the simple-string-comparison matching rule for redirect URIs (RFC 6749 §3.1.2.2):
/// the candidate URI must equal a single registered absolute URI. Optionally strips the query
/// and fragment from the candidate before comparison to accommodate clients that append
/// dynamic query parameters at runtime.
/// </summary>
public sealed class ExactMatchUriValidator : IUriValidator
{
	/// <summary>
	/// Creates a validator that accepts exactly <paramref name="validUri"/>.
	/// </summary>
	/// <param name="validUri">The single registered absolute URI to match against.</param>
	/// <param name="ignoreQueryAndFragment">When <c>true</c>, the candidate URI's query and
	/// fragment are stripped before comparison; otherwise comparison is exact, including those
	/// components.</param>
	/// <exception cref="ArgumentException"><paramref name="validUri"/> is not an absolute URI.</exception>
	public ExactMatchUriValidator(Uri validUri, bool ignoreQueryAndFragment = false)
	{
		if (validUri is not { IsAbsoluteUri: true })
			throw new ArgumentException($"{nameof(validUri)} must be absolute");

		_ignoreQueryAndFragment = ignoreQueryAndFragment;
		_validUri = validUri;
	}

	private readonly bool _ignoreQueryAndFragment;
	private readonly Uri _validUri;

	/// <summary>
	/// Validates the specified URI by checking for an exact match with the predefined URI.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	/// <returns><c>true</c> if the specified URI exactly matches the predefined URI, otherwise <c>false</c>.</returns>
	public bool IsValid(Uri uri)
	{
		if (_ignoreQueryAndFragment && (uri.Query.HasValue() || uri.Fragment.HasValue()))
		{
			uri = new System.UriBuilder(uri) { Query = null, Fragment = null }.Uri;
		}

		return _validUri == uri;
	}
}
