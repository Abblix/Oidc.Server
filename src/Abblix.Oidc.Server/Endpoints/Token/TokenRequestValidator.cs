// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Validates token requests against OAuth 2.0 specifications, ensuring that requests are properly formed and authorized.
/// This class plays a critical role in the OAuth 2.0 authentication and authorization process by verifying the integrity
/// and authenticity of token requests, according to the framework defined in RFC 6749.
/// </summary>
/// <param name="validator">The token context validator used to validate token requests.</param>
public class TokenRequestValidator(ITokenContextValidator validator) : ITokenRequestValidator
{
	/// <summary>
	/// Asynchronously validates a token request against the OAuth 2.0 specifications. It checks for proper authorization
	/// of the client, the validity of the grant type, and other request parameters. This process involves authenticating
	/// the client using the provided client authenticator and then delegating the grant-specific validation
	/// to the appropriate grant handler.
	/// </summary>
	/// <param name="tokenRequest">The token request containing all necessary parameters for validation.</param>
	/// <param name="clientRequest">Client request information necessary for client authentication.</param>
	/// <returns>A <see cref="Task"/> that resolves to a <see cref="Result{ValidTokenRequest, AuthError}"/>,
	/// indicating the outcome of the validation process. This result can either denote a successful validation
	/// or contain error information specifying why the request was invalid.</returns>
	/// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
	public async Task<Result<ValidTokenRequest, OidcError>> ValidateAsync(
		TokenRequest tokenRequest, ClientRequest clientRequest, CancellationToken cancellationToken)
	{
		var context = new TokenValidationContext(tokenRequest, clientRequest);

		var error = await validator.ValidateAsync(context, cancellationToken);
		if (error != null)
			return error;

		return new ValidTokenRequest(context);
	}
}
