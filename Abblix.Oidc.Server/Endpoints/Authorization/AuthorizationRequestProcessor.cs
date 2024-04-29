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

using System.Security.Cryptography;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using AuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;


namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Processes authorization requests by coordinating with various services like authentication,
/// consent, and token issuance. This class handles the logic of determining the appropriate
/// response to an authorization request based on the request's parameters and the current state
/// of the user's session.
/// </summary>
public class AuthorizationRequestProcessor : IAuthorizationRequestProcessor
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AuthorizationRequestProcessor"/> class.
	/// This constructor sets up the necessary services for processing authorization requests,
	/// including user authentication, consent handling, authorization code generation, access
	/// and identity token services, and time-related functionality.
	/// </summary>
	/// <param name="authSessionService">Service for handling user authentication.</param>
	/// <param name="consentService">Service for managing user consent.</param>
	/// <param name="authorizationCodeService">Service for generating and managing authorization codes.</param>
	/// <param name="accessTokenService">Service for creating access tokens.</param>
	/// <param name="identityTokenService">Service for generating identity tokens.</param>
	/// <param name="clock">Service for managing time-related operations.</param>
	public AuthorizationRequestProcessor(
		IAuthSessionService authSessionService,
		IConsentService consentService,
		IAuthorizationCodeService authorizationCodeService,
		IAccessTokenService accessTokenService,
		IIdentityTokenService identityTokenService,
		TimeProvider clock)
	{
		_authSessionService = authSessionService;
		_consentService = consentService;
		_authorizationCodeService = authorizationCodeService;
		_accessTokenService = accessTokenService;
		_identityTokenService = identityTokenService;
		_clock = clock;
	}

	private readonly IAccessTokenService _accessTokenService;
	private readonly IAuthorizationCodeService _authorizationCodeService;
	private readonly IAuthSessionService _authSessionService;
	private readonly IConsentService _consentService;
	private readonly IIdentityTokenService _identityTokenService;
	private readonly TimeProvider _clock;

	/// <summary>
	/// Asynchronously processes a valid authorization request.
	/// This method orchestrates the flow of handling an authorization request, including user authentication,
	/// consent validation, and token generation. It determines the appropriate response based on the request's
	/// parameters and the user's session state, which may include prompting for login, consent or directly generating
	/// authorization codes and tokens.
	/// </summary>
	/// <param name="request">The valid authorization request to process.</param>
	/// <returns>
	/// An <see cref="AuthorizationResponse"/> representing the outcome of the processed authorization request.
	/// This response could be a successful authentication, an error, or a requirement for further user interaction
	/// (like login or consent).
	/// </returns>
	public async Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request)
	{
		request.ClientInfo.CheckClient();
		var model = request.Model;

		var authSessions = await GetAvailableAuthSessionsAsync(model);

		if (authSessions.Count == 0 || model.Prompt == Prompts.Login)
		{
			if (model.Prompt == Prompts.None)
			{
				return new AuthorizationError(
					model,
					ErrorCodes.LoginRequired,
					"The Authorization Server requires End-User authentication.",
					request.ResponseMode,
					model.RedirectUri);
			}

			return new LoginRequired(model);
		}

		if (authSessions.Count > 1 || model.Prompt == Prompts.SelectAccount)
		{
			if (model.Prompt == Prompts.None)
			{
				return new AuthorizationError(
					model,
					ErrorCodes.AccountSelectionRequired,
					"The End-User is to select a session at the Authorization Server.",
					request.ResponseMode,
					model.RedirectUri);
			}

			return new AccountSelectionRequired(model, authSessions.ToArray());
		}

		var authSession = authSessions.Single();

		if (model.Prompt == Prompts.Consent || await _consentService.IsConsentRequired(request, authSession))
		{
			if (model.Prompt == Prompts.None)
			{
				return new AuthorizationError(
					model,
					ErrorCodes.ConsentRequired,
					"The Authorization Server requires End-User consent.",
					request.ResponseMode,
					model.RedirectUri);
			}

			return new ConsentRequired(model, authSession);
		}

		var clientId = request.ClientInfo.ClientId;
		var authContext = new AuthorizationContext(clientId, model.Scope, model.Claims)
		{
			RedirectUri = model.RedirectUri,
			Nonce = model.Nonce,
			CodeChallenge = model.CodeChallenge,
			CodeChallengeMethod = model.CodeChallengeMethod,
		};

		if (!authSession.AffectedClientIds.Contains(clientId))
		{
			authSession.AffectedClientIds.Add(clientId);
			await _authSessionService.SignInAsync(authSession);
		}

		var result = new SuccessfullyAuthenticated(
			model,
			request.ResponseMode,
			authSession.SessionId,
			authSession.AffectedClientIds);

		var codeRequired = request.Model.ResponseType.HasFlag(ResponseTypes.Code);
		if (codeRequired)
		{
			result.Code = await _authorizationCodeService.GenerateAuthorizationCodeAsync(
				authSession,
				authContext,
				request.ClientInfo);
		}

		var tokenRequired = request.Model.ResponseType.HasFlag(ResponseTypes.Token);
		if (tokenRequired)
		{
			result.TokenType = TokenTypes.Bearer;

			var accessToken = await _accessTokenService.CreateAccessTokenAsync(
				authSession,
				authContext,
				request.ClientInfo);

			result.AccessToken = accessToken;
		}

		var idTokenRequired = request.Model.ResponseType.HasFlag(ResponseTypes.IdToken);
		if (idTokenRequired)
		{
			var idToken = await _identityTokenService.CreateIdentityTokenAsync(
				authSession,
				authContext,
				request.ClientInfo,
				!codeRequired && !tokenRequired,
				result.Code,
				result.AccessToken?.EncodedJwt);

			result.IdToken = idToken;
		}

		return result;
	}

	private Task<List<AuthSession>> GetAvailableAuthSessionsAsync(AuthorizationRequest model)
	{
		var authSessions = _authSessionService.GetAvailableAuthSessions();

		if (model.MaxAge.HasValue)
		{
			// skip all sessions older than max_age value
			var minAuthenticationTime = _clock.GetUtcNow() - model.MaxAge;
			authSessions = authSessions
				.WhereAsync(session => minAuthenticationTime < session.AuthenticationTime);
		}

		var acrValues = model.AcrValues;
		if (acrValues is { Length: > 0 })
		{
			authSessions = authSessions
				.WhereAsync(session => session.AuthContextClassRef.HasValue() &&
				                       acrValues.Contains(session.AuthContextClassRef));
		}

		return authSessions.ToListAsync();
	}
}
