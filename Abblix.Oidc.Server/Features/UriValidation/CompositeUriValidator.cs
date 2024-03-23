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
/// Represents a composite URI validator that combines multiple URI validation strategies.
/// This class allows the integration of various URI validation rules and abstracts the complexity of individual
/// validations, providing a unified interface for URI validation.
/// </summary>
/// <remarks>
/// The CompositeUriValidator class follows the Composite Design Pattern, enabling the combination of different
/// URI validation strategies into a single cohesive unit. This class is particularly useful in scenarios where
/// URIs need to be validated against multiple criteria before being deemed valid.
/// </remarks>
public sealed class CompositeUriValidator : IUriValidator
{
	public CompositeUriValidator(IEnumerable<IUriValidator> validators)
	{
		_validators = validators;
	}

	public CompositeUriValidator(params IUriValidator[] validators)
		: this((IEnumerable<IUriValidator>)validators)
	{
	}

	private readonly IEnumerable<IUriValidator> _validators;

	/// <summary>
	/// Determines whether the specified URI is valid based on the criteria of all validators in the composite.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	/// <returns>
	/// <c>true</c> if the URI passes the validation rules of all included validators; otherwise, <c>false</c>.
	/// </returns>
	public bool IsValid(Uri uri) => _validators.Any(validator => validator.IsValid(uri));
}
