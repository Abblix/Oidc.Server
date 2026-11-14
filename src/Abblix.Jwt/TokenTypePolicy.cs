// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Which <c>typ</c> header values (RFC 7515 section 4.1.9) a validation accepts, so that a token signed for one
/// purpose cannot be presented as another by a recipient trusting the same issuer for several (RFC 8725
/// section 3.11).
/// </summary>
/// <remarks>
/// Every validation states one: <see cref="ValidationParameters.TokenTypes"/> has no default, because a default
/// that skipped the check would leave a type unchecked without anybody deciding it should be.
/// <para>
/// Matching is case-insensitive and accepts either spelling of the <c>application/</c> prefix on either side, so
/// <c>at+jwt</c> and <c>application/AT+JWT</c> name the same type, as RFC 7515 section 4.1.9 requires of a media
/// type.
/// </para>
/// </remarks>
public sealed record TokenTypePolicy
{
	private TokenTypePolicy(TokenTypeRule rule, IReadOnlyList<string> types)
	{
		Rule = rule;
		Types = types;
	}

	/// <summary>
	/// How the <c>typ</c> header is judged.
	/// </summary>
	public TokenTypeRule Rule { get; }

	/// <summary>
	/// The accepted <c>typ</c> values; empty for <see cref="CheckedByCaller"/>, and for
	/// <see cref="OrUntyped"/> when only a token without a type is accepted.
	/// </summary>
	public IReadOnlyList<string> Types { get; }

	/// <summary>
	/// Accepts a token whose <c>typ</c> names one of <paramref name="types"/>, and refuses one without a type.
	/// </summary>
	/// <param name="types">The accepted values, at least one.</param>
	public static TokenTypePolicy Exactly(params string[] types)
	{
		if (types.Length == 0)
			throw new ArgumentException("At least one token type is required.", nameof(types));

		return new TokenTypePolicy(TokenTypeRule.Exactly, types);
	}

	/// <summary>
	/// Accepts a token whose <c>typ</c> names one of <paramref name="types"/> or that carries no <c>typ</c>, for a
	/// token whose specification leaves its type optional. With no types, only an untyped token is accepted.
	/// </summary>
	/// <param name="types">The accepted values besides absence.</param>
	public static TokenTypePolicy OrUntyped(params string[] types) => new(TokenTypeRule.OrUntyped, types);

	/// <summary>
	/// Leaves the <c>typ</c> header to the caller, which judges it after validation, as a deliberate and named
	/// choice rather than a missing setting.
	/// </summary>
	public static readonly TokenTypePolicy CheckedByCaller = new(TokenTypeRule.CheckedByCaller, []);
}
