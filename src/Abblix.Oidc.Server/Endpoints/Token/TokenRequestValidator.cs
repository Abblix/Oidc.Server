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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Validates token requests against OAuth 2.0 specifications, ensuring that requests are properly formed and authorized.
/// This class plays a critical role in the OAuth 2.0 authentication and authorization process by verifying the integrity
/// and authenticity of token requests, according to the framework defined in RFC 6749.
/// </summary>
/// <param name="validator">The token context validator used to validate token requests.</param>
/// <param name="clientInfoProvider">The client store, asked through a lookup made for each request.</param>
public class TokenRequestValidator(ITokenContextValidator validator, IClientInfoProvider clientInfoProvider)
	: ITokenRequestValidator
{
	/// <summary>
	/// Asynchronously validates a token request against the OAuth 2.0 specifications. It checks for proper authorization
	/// of the client, the validity of the grant type, and other request parameters. This process involves authenticating
	/// the client using the provided client authenticator and then delegating the grant-specific validation
	/// to the appropriate grant handler.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="tokenRequest">The token request containing all necessary parameters for validation.</param>
	/// <param name="clientRequest">Client request information necessary for client authentication.</param>
	/// <returns>A <see cref="Task"/> that resolves to a <see cref="Result{ValidTokenRequest, AuthError}"/>,
	/// indicating the outcome of the validation process. This result can either denote a successful validation
	/// or contain error information specifying why the request was invalid.</returns>
	/// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
	public async Task<Result<ValidTokenRequest, OidcError>> ValidateAsync(
		TenantDefinition tenant,
		TokenRequest tokenRequest, ClientRequest clientRequest, CancellationToken cancellationToken)
	{
		// One lookup of the clients for the whole request: the client authentication and the reading of a token the
		// request presents find each client once
		var clients = new RequestScopedClientInfoProvider(clientInfoProvider);
		var context = new TokenValidationContext(tokenRequest, clientRequest) { Clients = clients };

		var error = await validator.ValidateAsync(tenant, context, cancellationToken);
		if (error == null)
			return new ValidTokenRequest(context);

		// draft-ietf-oauth-client-id-metadata-document-03 section 6.1: "At the token endpoint ... for a transient
		// failure, an HTTP 503 status code", whichever step of the request met the client that could not be had: its
		// authentication, or the reading of a token issued to it. A refusal alone: a request that passed validation may
		// already have spent its grant, a device code or a backchannel authentication request taken from storage
		return clients.RefusalOf(error);
	}
}
