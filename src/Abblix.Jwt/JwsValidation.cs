// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The JWS side of token validation: the header chain, then the claims chain.
/// </summary>
/// <param name="headerChain">Reads the token and checks its algorithm, signature and critical header parameters.
/// </param>
/// <param name="claimsChain">Checks the token's type, issuer, audience and lifetime.</param>
/// <param name="signingAlgorithmsProvider">The signing algorithms the registered signers serve.</param>
internal sealed class JwsValidation(
	JwsHeaderChain headerChain,
	JwtClaimsChain claimsChain,
	SigningAlgorithmsProvider signingAlgorithmsProvider)
{
	/// <summary>The signing algorithms a JWS may be validated under.</summary>
	public IEnumerable<string> SigningAlgorithmsSupported => signingAlgorithmsProvider.Algorithms;

	/// <summary>
	/// The token the compact JWS <paramref name="jwtParts"/> carries, once every link of both chains holds; the first
	/// error otherwise. The header links run first because they are the cheapest and most categorical, so a malformed
	/// or attacker-supplied token is refused before any callback the host supplied is invoked.
	/// </summary>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		string[] jwtParts,
		ValidationParameters parameters)
		=> headerChain.ValidateAsync(jwtParts, parameters)
			.BindAsync(token => claimsChain.ValidateAsync(token, parameters));
}
