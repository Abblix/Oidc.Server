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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
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
	/// Constructor that initializes the required services for handling authorization requests.
	/// These services collectively enable the class to handle key parts of the OAuth2/OpenID Connect flow,
	/// such as authenticating users, managing user consent, issuing tokens, and handling authorization codes.
	/// </summary>
	/// <param name="authSessionService">Handles user authentication sessions.</param>
	/// <param name="consentsProvider">Manages the storage and retrieval of user consent data.</param>
	/// <param name="authorizationCodeService">Generates and validates authorization codes during
	/// the authorization process.</param>
	/// <param name="accessTokenService">Issues access tokens upon successful authorization.</param>
	/// <param name="identityTokenService">Generates ID tokens for user identity verification in OIDC.</param>
	/// <param name="clock">Facilitates time-based logic (e.g., token expiration, session timeouts).</param>
	public AuthorizationRequestProcessor(
		IAuthSessionService authSessionService,
		IUserConsentsProvider consentsProvider,
		IAuthorizationCodeService authorizationCodeService,
		IAccessTokenService accessTokenService,
		IIdentityTokenService identityTokenService,
		TimeProvider clock)
	{
		_authSessionService = authSessionService;
		_consentsProvider = consentsProvider;
		_authorizationCodeService = authorizationCodeService;
		_accessTokenService = accessTokenService;
		_identityTokenService = identityTokenService;
		_clock = clock;
	}

	private readonly IAccessTokenService _accessTokenService;
	private readonly IAuthorizationCodeService _authorizationCodeService;
	private readonly IAuthSessionService _authSessionService;
	private readonly IUserConsentsProvider _consentsProvider;
	private readonly IIdentityTokenService _identityTokenService;
	private readonly TimeProvider _clock;

	/// <summary>
	/// Orchestrates the flow for handling a valid authorization request, considering the user's session state,
	/// the need for user consent, and generating appropriate tokens. This method serves as the central logic for
	/// determining how the system should respond based on the client's request and the user's current state.
	/// </summary>
	/// <param name="request">A validated authorization request containing parameters required for processing.</param>
	/// <returns>
	/// An authorization response object, which can either represent a successful authentication, an error,
	/// or a signal that further user interaction is required (e.g., login, consent).
	/// </returns>
	public async Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request)
	{
		// Ensures the client is permitted to make requests by the current license.
		request.ClientInfo.CheckClientLicense();

		var model = request.Model;

		// Retrieves any available user authentication sessions, filtered by the request’s parameters.
		var authSessions = await GetAvailableAuthSessionsAsync(model);

		AuthSession authSession;
		switch (authSessions.Count, model.Prompt)
		{
			// If no sessions exist and the prompt forbids user interaction,
			// respond that login is required without allowing user interaction.
			case (0, Prompts.None):
				return new AuthorizationError(
					model,
					ErrorCodes.LoginRequired,
					"The Authorization Server requires End-User authentication.",
					request.ResponseMode,
					model.RedirectUri);

			// If multiple sessions exist but the prompt forbids interaction,
			// respond that account selection is required but user interaction is not allowed.
			case (> 1, Prompts.None):
				return new AuthorizationError(
					model,
					ErrorCodes.AccountSelectionRequired,
					"The End-User is to select a session at the Authorization Server.",
					request.ResponseMode,
					model.RedirectUri);

			// If no sessions exist, or the request explicitly asks for a login, prompt the user for login.
			case (0, _) or (_, Prompts.Login):
				// Otherwise, prompt the user to log in.
				return new LoginRequired(model);

			// If multiple sessions exist, or the request requires account selection, prompt the user to select an account.
			case (> 1, _) or (_, Prompts.SelectAccount):
				return new AccountSelectionRequired(model, authSessions.ToArray());

			// If a single session exists, proceed with that session for further processing.
			case (1, _):
				authSession = authSessions.Single();
				break;

			// Catch any unexpected cases where the session count or prompt state does not match the expected conditions.
			default:
				throw new InvalidOperationException(
					$"Unexpected number of auth sessions: {authSessions.Count} or prompt: {model.Prompt}");
		}

		// Retrieve user consents (i.e., permissions granted for requested scopes/resources).
		// The 'prompt=consent' case is not forgotten but processed inside this call.
		var userConsents = await _consentsProvider.GetUserConsentsAsync(request, authSession);

		// If consent for required scopes or resources is still pending, handle consent requirements.
		if (userConsents.Pending is { Scopes.Length: > 0 } or { Resources.Length: > 0 })
		{
			// If user interaction is disallowed but consent is necessary, return an error.
			if (model.Prompt == Prompts.None)
			{
				return new AuthorizationError(
					model,
					ErrorCodes.ConsentRequired,
					"The Authorization Server requires End-User consent.",
					request.ResponseMode,
					model.RedirectUri);
			}

			// Prompt for consent if necessary permissions are not yet granted.
			return new ConsentRequired(model, authSession, userConsents.Pending);
		}

		var clientId = request.ClientInfo.ClientId;

		// Build an authorization context containing necessary data like client ID, scopes, and claims.
		// The authorization context is used to carry the granted scopes, resources and other key details through
		// the flow.
		var authContext = new AuthorizationContext(
			clientId,
			userConsents.Granted.Scopes,
			userConsents.Granted.Resources,
			model.Claims)
		{
			RedirectUri = model.RedirectUri,
			Nonce = model.Nonce,
			CodeChallenge = model.CodeChallenge,
			CodeChallengeMethod = model.CodeChallengeMethod,
		};

		// Mark the client as affected by this session and update the session's state.
		// Ensures the client is tied to the current session, updating its state to include the session's client ID.
		if (!authSession.AffectedClientIds.Contains(clientId))
		{
			authSession.AffectedClientIds.Add(clientId);
			await _authSessionService.SignInAsync(authSession);
		}

		// Initialize a successful authentication result.
		var result = new SuccessfullyAuthenticated(
			model,
			request.ResponseMode,
			authSession.SessionId,
			authSession.AffectedClientIds);

		// Check if the response type requires an authorization code, and generate it if needed.
		var codeRequired = request.Model.ResponseType.HasFlag(ResponseTypes.Code);
		if (codeRequired)
		{
			result.Code = await _authorizationCodeService.GenerateAuthorizationCodeAsync(
				new AuthorizedGrant(authSession, authContext),
				request.ClientInfo.AuthorizationCodeExpiresIn);
		}

		// Check if an access token is required, and generate it if needed.
		var tokenRequired = request.Model.ResponseType.HasFlag(ResponseTypes.Token);
		if (tokenRequired)
		{
			result.TokenType = TokenTypes.Bearer;
			result.AccessToken = await _accessTokenService.CreateAccessTokenAsync(
				authSession,
				authContext,
				request.ClientInfo);
		}

		// Check if an ID token is required, and generate it if needed.
		var idTokenRequired = request.Model.ResponseType.HasFlag(ResponseTypes.IdToken);
		if (idTokenRequired)
		{
			result.IdToken = await _identityTokenService.CreateIdentityTokenAsync(
				authSession,
				authContext,
				request.ClientInfo,
				!codeRequired && !tokenRequired,
				result.Code,
				result.AccessToken?.EncodedJwt);
		}

		// Return the final authorization result containing codes and tokens as needed.
		return result;
	}

	/// <summary>
	/// Retrieves the available authentication sessions based on the request's constraints (e.g., max age, ACR values).
	/// This function ensures that only sessions meeting the request's criteria (e.g., recency, security level) are used.
	/// </summary>
	/// <param name="model">The authorization request containing parameters like max age and ACR values.</param>
	/// <returns>A list of valid authentication sessions that match the request's criteria.</returns>
	private ValueTask<List<AuthSession>> GetAvailableAuthSessionsAsync(AuthorizationRequest model)
	{
		var authSessions = _authSessionService.GetAvailableAuthSessions();

		// Filter sessions based on the maximum allowable authentication age, if specified.
		if (model.MaxAge.HasValue)
		{
			// skip all sessions older than max_age value
			var minAuthenticationTime = _clock.GetUtcNow() - model.MaxAge;
			authSessions = authSessions
				.Where(session => minAuthenticationTime < session.AuthenticationTime);
		}

		// Filter sessions based on the required ACR (Authentication Context Class Reference) values, if specified.
		var acrValues = model.AcrValues;
		if (acrValues is { Length: > 0 })
		{
			authSessions = authSessions.Where(
				session => session.AuthContextClassRef.HasValue() && acrValues.Contains(session.AuthContextClassRef));
		}

		// Return the filtered list of sessions as an asynchronous task.
		return authSessions.ToListAsync();
	}
}
