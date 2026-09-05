// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
