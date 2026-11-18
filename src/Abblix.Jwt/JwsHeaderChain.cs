// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The first half of the JWS validation chain (Chain of Responsibility): reads the token, then checks its algorithm,
/// its signature and its critical header parameters, each link passing the token on or ending the chain with its
/// error.
/// </summary>
/// <remarks>
/// These links come first because they are the cheapest and most categorical, so a malformed or attacker-supplied
/// token is refused before any callback the host supplied is invoked.
/// </remarks>
/// <param name="signer">Verifies the signature against the candidate keys.</param>
/// <param name="serviceProvider">Resolves registered <see cref="ICriticalHeaderHandler"/>
/// instances by JWS 'crit' header name (RFC 7515 section 4.1.11). Handlers are registered as keyed
/// singletons via <see cref="ServiceCollectionExtensions.AddCriticalHeaderHandler{THandler}"/>;
/// the chain routes a 'crit' name to its handler with
/// <c>GetKeyedService&lt;ICriticalHeaderHandler&gt;(name)</c> at validation time. With no
/// handler registered (the default) the library understands no crit extensions and rejects
/// every well-formed 'crit' header.</param>
internal sealed class JwsHeaderChain(IJsonWebTokenSigner signer, IServiceProvider serviceProvider)
{
	private readonly JwsSignatureValidator _signatureValidator = new(signer);
	private readonly JwsCriticalHeaderValidator _criticalHeaderValidator = new(serviceProvider);

	/// <summary>
	/// The token the compact JWS <paramref name="jwtParts"/> carries, once its header and signature hold; the
	/// first error otherwise.
	/// </summary>
	public Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		string[] jwtParts,
		ValidationParameters parameters)
		=> JwsCompactParser.Parse(jwtParts)
			.Bind(token => JwsAlgorithmValidator.Validate(token, parameters))
			.BindAsync(token => _signatureValidator.ValidateSignatureAsync(token, jwtParts, parameters))
			.BindAsync(token => _criticalHeaderValidator.ValidateAsync(token, parameters));
}
