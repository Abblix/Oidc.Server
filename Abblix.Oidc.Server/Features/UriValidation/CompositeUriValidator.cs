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
/// Aggregates several <see cref="IUriValidator"/> instances under OR semantics: a URI is
/// accepted as soon as any of the wrapped validators accepts it. Used to back a client whose
/// configuration registers multiple equally-valid URIs (for example, several registered redirect
/// URIs for the same client).
/// </summary>
/// <param name="validators">The validators to combine; evaluation short-circuits on the first match.</param>
public sealed class CompositeUriValidator(IEnumerable<IUriValidator> validators) : IUriValidator
{
	/// <summary>
	/// Convenience constructor for a fixed-arity validator list.
	/// </summary>
	public CompositeUriValidator(params IUriValidator[] validators)
		: this((IEnumerable<IUriValidator>)validators)
	{
	}

	/// <summary>
	/// Returns <c>true</c> as soon as any wrapped validator accepts <paramref name="uri"/>;
	/// returns <c>false</c> only when every validator rejects it.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	public bool IsValid(Uri uri) => validators.Any(validator => validator.IsValid(uri));
}
