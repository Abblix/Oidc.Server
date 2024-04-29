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
