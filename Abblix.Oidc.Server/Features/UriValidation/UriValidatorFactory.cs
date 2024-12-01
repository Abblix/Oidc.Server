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
/// Provides a factory method for creating URI validators. Depending on the number of URIs provided,
/// it creates either a single exact match validator or a composite validator that combines multiple exact
/// match validators.
/// </summary>
public static class UriValidatorFactory
{
	/// <summary>
	/// Creates a URI validator based on the given URIs.
	/// If only one URI is provided, it returns an <see cref="ExactMatchUriValidator"/> for that URI.
	/// If multiple URIs are provided, it returns a <see cref="CompositeUriValidator"/> that validates against
	/// all given URIs.
	/// </summary>
	/// <param name="validUris">An array of URIs to be used for validation.</param>
	/// <returns>
	/// An <see cref="IUriValidator"/> instance that can validate URIs based on the provided URIs.
	/// Returns an <see cref="ExactMatchUriValidator"/> for a single URI or a <see cref="CompositeUriValidator"/>
	/// for multiple URIs.
	/// </returns>
	/// <remarks>
	/// Use this method when you want to create a validator with default behavior for handling query strings
	/// and fragments during validation.
	/// </remarks>
	public static IUriValidator Create(params Uri[] validUris)
		=> Create(false, validUris);

	/// <summary>
	/// Creates a URI validator based on the given URIs,
	/// with an option to ignore query strings and fragments during validation.
	/// </summary>
	/// <param name="ignoreQueryAndFragment">
	/// Specifies whether query strings and fragments should be ignored during validation.</param>
	/// <param name="validUris">An array of URIs to be used for validation.</param>
	/// <returns>
	/// An <see cref="IUriValidator"/> instance that can validate URIs based on the provided URIs.
	/// Returns an <see cref="ExactMatchUriValidator"/> for a single URI or a <see cref="CompositeUriValidator"/>
	/// for multiple URIs.
	/// </returns>
	/// <remarks>
	/// - If only one URI is provided, an <see cref="ExactMatchUriValidator"/> is returned.
	/// - If multiple URIs are provided, a <see cref="CompositeUriValidator"/> is returned, which validates
	///   against all specified URIs.
	/// - The `ignoreQueryAndFragment` parameter determines whether query strings and fragments in URIs
	///   are considered during validation.
	/// </remarks>
	public static IUriValidator Create(bool ignoreQueryAndFragment, params Uri[] validUris)
		=> validUris.Length switch
		{
			1 => new ExactMatchUriValidator(validUris[0], ignoreQueryAndFragment),
			_ => new CompositeUriValidator(
				from validUri in validUris
				select new ExactMatchUriValidator(validUri, ignoreQueryAndFragment)),
		};
}
