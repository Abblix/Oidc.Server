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

using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Validates a URI based on an exact match against a predefined value, disregarding the query and fragment parts.
/// </summary>
public sealed class ExactMatchUriValidator : IUriValidator
{
	public ExactMatchUriValidator(Uri validUri, bool ignoreQueryAndFragment = false)
	{
		if (!validUri.IsAbsoluteUri)
		{
			throw new ArgumentException($"{nameof(validUri)} must be absolute");
		}
		_validUri = validUri;
		_ignoreQueryAndFragment = ignoreQueryAndFragment;
	}

	private readonly Uri _validUri;
	private readonly bool _ignoreQueryAndFragment;

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
