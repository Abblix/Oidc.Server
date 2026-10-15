// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Implements the simple-string-comparison matching rule for redirect URIs (RFC 6749 section 3.1.2.2):
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

		// A registered request URI carries the hash of the file it names as its fragment, which changes with the
		// file (OpenID Connect Dynamic Client Registration 1.0 section 2, request_uris), so in the ignoring mode the
		// fragment is left out on the registered side as well
		_components = ignoreQueryAndFragment switch
		{
			true => UriComponents.AbsoluteUri & ~UriComponents.Fragment,
			false => UriComponents.AbsoluteUri,
		};
	}

	private readonly bool _ignoreQueryAndFragment;
	private readonly Uri _validUri;
	private readonly UriComponents _components;

	/// <summary>
	/// Validates the specified URI by checking for an exact match with the predefined URI.
	/// </summary>
	/// <remarks>
	/// By default user information and the fragment take part in the comparison, so a candidate carrying either is
	/// refused unless the registered URI carries the same: <see cref="Uri"/> equality ignores both, while RFC 6749
	/// section 3.1.2 forbids a fragment in a redirection endpoint and a registered URI carries no user information.
	/// In the mode ignoring the query and fragment, the candidate's query and fragment are dropped and the registered
	/// URI's fragment is not compared, so only user information is still refused there.
	/// </remarks>
	/// <param name="uri">The URI to validate.</param>
	/// <returns><c>true</c> if the specified URI exactly matches the predefined URI, otherwise <c>false</c>.</returns>
	public bool IsValid(Uri uri)
	{
		if (_ignoreQueryAndFragment && (uri.Query.HasValue() || uri.Fragment.HasValue()))
		{
			uri = new System.UriBuilder(uri) { Query = null, Fragment = null }.Uri;
		}

		return uri.IsAbsoluteUri
		       && Uri.Compare(_validUri, uri, _components, UriFormat.SafeUnescaped, StringComparison.Ordinal) == 0;
	}
}
