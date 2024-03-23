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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Validates token requests against OAuth 2.0 specifications, ensuring that requests are properly formed and authorized.
/// This class plays a critical role in the OAuth 2.0 authentication and authorization process by verifying the integrity and
/// authenticity of token requests according to the framework defined in RFC 6749.
/// </summary>
public class TokenRequestValidator : ITokenRequestValidator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="TokenRequestValidator"/> class.
	/// Sets up the validator with the necessary components for client authentication and handling different
	/// authorization grant types. Client authentication follows the process described in RFC 6749, Section 2.3.
	/// </summary>
	/// <param name="clientAuthenticator">The authenticator used for validating client requests.</param>
	/// <param name="grantHandler">A grant handler responsible for different types of authorization grants.</param>
	public TokenRequestValidator(
		IClientAuthenticator clientAuthenticator,
		IAuthorizationGrantHandler grantHandler)
	{
		_clientAuthenticator = clientAuthenticator;
		_grantHandler = grantHandler;
	}

	private readonly IClientAuthenticator _clientAuthenticator;
	private readonly IAuthorizationGrantHandler _grantHandler;

	/// <summary>
	/// Asynchronously validates a token request against the OAuth 2.0 specifications. It checks for proper authorization
	/// of the client, the validity of the grant type, and other request parameters. This process involves authenticating
	/// the client using the provided client authenticator and then delegating the grant-specific validation
	/// to the appropriate grant handler.
	/// </summary>
	/// <param name="tokenRequest">The token request containing all necessary parameters for validation.</param>
	/// <param name="clientRequest">Client request information necessary for client authentication.</param>
	/// <returns>A <see cref="Task"/> that resolves to a <see cref="TokenRequestValidationResult"/>,
	/// indicating the outcome of the validation process. This result can either denote a successful validation
	/// or contain error information specifying why the request was invalid.</returns>
	public async Task<TokenRequestValidationResult> ValidateAsync(TokenRequest tokenRequest, ClientRequest clientRequest)
	{
		if (tokenRequest.Resource != null)
		{
			foreach (var resource in tokenRequest.Resource)
			{
				if (!resource.IsAbsoluteUri)
				{
					return new TokenRequestError(
						ErrorCodes.InvalidTarget,
						"The resource must be absolute URI");
				}
				if (resource.Fragment.HasValue())
				{
					return new TokenRequestError(
						ErrorCodes.InvalidTarget,
						"The resource must not contain fragment");
				}
			}
		}

		var clientInfo = await _clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
		if (clientInfo == null)
		{
			return new TokenRequestError(ErrorCodes.InvalidClient, "The client is not authorized");
		}

		var result = await _grantHandler.AuthorizeAsync(tokenRequest, clientInfo);
		return result switch
		{
			InvalidGrantResult { Error: var error, ErrorDescription: var description }
				=> new TokenRequestError(error, description),

			AuthorizedGrantResult { Context.RedirectUri: var redirectUri }
				when redirectUri != tokenRequest.RedirectUri
				=> new TokenRequestError(
					ErrorCodes.InvalidGrant,
					"The redirect Uri value does not match to the value used before"),

			AuthorizedGrantResult
				{
					AuthSession: var authSession,
					Context: var context,
					RefreshToken: var refreshToken,
					IssuedTokens: var issuedTokens,
				}
				=> new ValidTokenRequest(tokenRequest, authSession, context, clientInfo, refreshToken, issuedTokens),

			_ => throw new UnexpectedTypeException(nameof(result), result.GetType()),
		};
	}
}
