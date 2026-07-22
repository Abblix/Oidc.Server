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

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Licensing;
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
public class AuthorizationRequestProcessor(
	IAuthSessionService authSessionService,
	IUserConsentsProvider consentsProvider,
	TimeProvider clock,
	IEnumerable<IAuthorizationResponseBuilder> responseProcessors,
	IConsentConstraintEnforcer consentConstraintEnforcer) : IAuthorizationRequestProcessor
{
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
		var authSessions = await GetAvailableAuthSessionsAsync(model, request.ClientInfo);

		AuthSession authSession;
		switch (authSessions.Count, model.Prompt)
		{
			// Initiating User Registration via OpenID Connect 1.0: prompt=create takes the user to
			// the account-creation experience regardless of whether a session exists. An OP that
			// advertises create in prompt_values_supported must act on it — previously the value
			// fell through to the generic branches and the registration intent was silently lost.
			case (_, Prompts.Create):
				return new RegistrationRequired(model);

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

		// Retrieve user consents (i.e., permissions granted for requested scopes/resources/authorization_details).
		// The 'prompt=consent' case is not forgotten but processed inside this call.
		var userConsents = await consentsProvider.GetUserConsentsAsync(request, authSession);

		// If consent for required scopes, resources, or authorization_details is still pending, handle it.
		if (userConsents.Pending is { Scopes.Length: > 0 }
			or { Resources.Length: > 0 }
			or { AuthorizationDetails.Count: > 0 })
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

		// RFC 9396 §5: a consent provider may narrow or deny authorization_details entries.
		//   Granted.AuthorizationDetails == null    -> legacy provider, no AD opinion; pass through what the
		//                                              validator pipeline produced (backward compat with PR #135).
		//   Granted.AuthorizationDetails is { Count: 0 } AND the request carried AD entries
		//                                           -> user denied every entry; fail with access_denied.
		//   Granted.AuthorizationDetails is non-empty -> explicit consent (possibly narrowed); emit as-is.
		if (userConsents.Granted.AuthorizationDetails is { Count: 0 }
			&& request.AuthorizationDetails is { Count: > 0 })
		{
			return new AuthorizationError(
				model,
				ErrorCodes.AccessDenied,
				"The end-user denied consent for all requested authorization_details entries.",
				request.ResponseMode,
				model.RedirectUri);
		}

		// Defense-in-depth backstop: the IUserConsentsProvider contract permits a NARROWER grant
		// than the request, never a broader one. Assert that invariant before the granted set
		// reaches the issued token. A violation is a host-side defect (a buggy consent provider, or
		// browser tampering it failed to intersect against the request), so it surfaces as an
		// exception rather than an escalated grant. Symmetric with the strictly narrowing-only
		// TokenAuthorizationContextEvaluator at the token endpoint.
		await consentConstraintEnforcer.EnforceAsync(request, userConsents.Granted, CancellationToken.None);

		// C2 (PR #135 review): the JsonArray reference passed to the consent provider and the
		// one placed on AuthorizationContext travel through System.Text.Json on the way to the
		// issued JWT. If a host's IUserConsentsProvider impl parents the borrowed array as a
		// child of its own DTO, the second serialise will throw because the JsonNode is parented
		// twice. DeepClone defensively on the boundary so the two consumers each see independent
		// trees -- matches the DeepClone discipline applied elsewhere (ApplyTo, resolvers).
		var sourceAd = userConsents.Granted.AuthorizationDetails ?? request.AuthorizationDetails;
		var emittedAuthorizationDetails = sourceAd is { Count: > 0 }
			? (JsonArray?)sourceAd.DeepClone()
			: null;

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
			ProofKeyThumbprint = model.ProofKeyThumbprint,
			AuthorizationDetails = emittedAuthorizationDetails,
		};

		// Mark the client as affected by this session and update the session's state.
		// Ensures the client is tied to the current session, updating its state to include the session's client ID.
		if (!authSession.AffectedClientIds.Contains(clientId))
		{
			authSession.AffectedClientIds.Add(clientId);
			await authSessionService.SignInAsync(authSession);
		}

		// Initialize a successful authentication result. GrantedScopes carries the consent-narrowed
		// scope set (identical to what the issued token carries) so the response encoder advertises the
		// granted scope on the front-channel scope parameter, not the broader requested set (RFC 6749 §3.3)
		var result = new SuccessfullyAuthenticated(
			model,
			request.ResponseMode,
			authSession.SessionId,
			authSession.AffectedClientIds)
		{
			GrantedScopes = authContext.Scope,
		};

		var authorizedGrant = new AuthorizedGrant(authSession, authContext);

		// Dispatch each requested response-type part to its registered builder. The DI
		// registration order — AuthorizationCodeBuilder in the core registration, then
		// TokenResponseBuilder and IdTokenResponseBuilder added by EnableImplicitFlow —
		// preserves the dependency IdTokenResponseBuilder has on the code and access-token
		// fields populated by earlier builders (used to compute c_hash / at_hash). Parts
		// whose builders are not registered (e.g. token / id_token when Implicit Flow is not
		// enabled) cannot reach this point: FlowTypeValidator rejects the request earlier
		// with unsupported_response_type.
		foreach (var processor in responseProcessors)
		{
			if (!request.Model.ResponseType.HasFlag(processor.ResponseType))
				continue;

			await processor.BuildResponseAsync(request, authorizedGrant, result);
		}

		// Return the final authorization result containing codes and tokens as needed.
		return result;
	}

	/// <summary>
	/// Retrieves the available authentication sessions based on the request's constraints (e.g., max age, ACR values).
	/// This function ensures that only sessions meeting the request's criteria (e.g., recency, security level) are used.
	/// </summary>
	/// <param name="model">The authorization request containing parameters like max age and ACR values.</param>
	/// <param name="clientInfo">The client, supplying default_max_age / default_acr_values fallbacks.</param>
	/// <returns>A list of valid authentication sessions that match the request's criteria.</returns>
	private ValueTask<List<AuthSession>> GetAvailableAuthSessionsAsync(AuthorizationRequest model, ClientInfo clientInfo)
	{
		var authSessions = authSessionService.GetAvailableAuthSessions();

		// Filter by maximum authentication age. When the request omits max_age, fall back to the
		// client's registered default_max_age (OIDC Core §2 / §3.1.2.1).
		var maxAge = model.MaxAge ?? clientInfo.DefaultMaxAge;
		if (maxAge.HasValue)
		{
			// skip all sessions older than the effective max_age value
			var minAuthenticationTime = clock.GetUtcNow() - maxAge;
			authSessions = authSessions.Where(session => minAuthenticationTime < session.AuthenticationTime);
		}

		// Filter by required ACR values. When the request omits acr_values, fall back to the client's
		// registered default_acr_values (OIDC Core §2).
		var acrValues = model.AcrValues is { Length: > 0 } requestedAcrValues
			? requestedAcrValues
			: clientInfo.DefaultAcrValues;
		if (acrValues is { Length: > 0 })
		{
			authSessions = authSessions.Where(
				session => session.AuthContextClassRef.HasValue() && acrValues.Contains(session.AuthContextClassRef));
		}

		// Return the filtered list of sessions as an asynchronous task.
		return authSessions.ToListAsync();
	}
}
