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

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Provides a factory method for creating URI validators. Depending on the number of URIs provided,
/// it creates either a single exact match validator or a composite validator that combines multiple exact match validators.
/// </summary>
public static class UriValidatorFactory
{
	/// <summary>
	/// Creates a URI validator based on the given URIs.
	/// If only one URI is provided, it returns an <see cref="ExactMatchUriValidator"/> for that URI.
	/// If multiple URIs are provided, it returns a <see cref="CompositeUriValidator"/> that validates against all given URIs.
	/// </summary>
	/// <param name="validUris">An array of URIs to be used for validation.</param>
	/// <returns>
	/// An <see cref="IUriValidator"/> instance that can validate URIs based on the provided URIs.
	/// Returns an <see cref="ExactMatchUriValidator"/> for a single URI or a <see cref="CompositeUriValidator"/> for multiple URIs.
	/// </returns>
	public static IUriValidator Create(params Uri[] validUris)
		=> validUris.Length switch
		{
			1 => new ExactMatchUriValidator(validUris[0]),
			_ => new CompositeUriValidator(from validUri in validUris select new ExactMatchUriValidator(validUri)),
		};
}
