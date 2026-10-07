// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using AuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Processes authorization requests by coordinating with various services like authentication,
/// consent, and token issuance. This class handles the logic of determining the appropriate
/// response to an authorization request based on the request's parameters and the current state
/// of the user's session.
/// </summary>
[SuppressMessage("SonarQube", "S107:Methods should not have too many parameters",
	Justification = "Every dependency is used: the session store, the record of which clients a session has, the consent provider and its backstop, the revocation check, the subject converter, the clock and the response builders each decide a different part of one authorization.")]
public class AuthorizationRequestProcessor(
	IAuthSessionService authSessionService,
	ISessionClientRegistry sessionClients,
	IUserConsentsProvider consentsProvider,
	IRevocationCutoffChecker cutoffChecker,
	ISubjectTypeConverter subjectTypeConverter,
	TimeProvider clock,
	IEnumerable<IAuthorizationResponseBuilder> responseProcessors,
	IConsentConstraintEnforcer consentConstraintEnforcer) : IAuthorizationRequestProcessor
{
	// Extracted collaborator: which session answers the request is one question with its own dependencies,
	// built here from the constructor's arguments so the processor's public constructor stays as hosts call it.
	private readonly UserConsentsReader _consentsReader = new(consentsProvider);

	private readonly AuthSessionSelector _sessionSelector =
		new(authSessionService, cutoffChecker, subjectTypeConverter, clock);

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

		var selected = await _sessionSelector.SelectAsync(request);
		return await selected.MatchAsync(
			authSession => AuthorizeAsync(request, authSession),
			answered => answered);
	}

	/// <summary>
	/// Authorizes the request with the session selected for it: asks for the consent still owed, or issues
	/// what the request asked for.
	/// </summary>
	private async Task<AuthorizationResponse> AuthorizeAsync(ValidAuthorizationRequest request, AuthSession authSession)
	{
		var model = request.Model;

		// What the request asked for, read BEFORE the provider sees it. The provider is a host seam and it
		// is handed the array this request carries, while every decision below is measured against that same
		// array: whether the end user denied everything, what the granted set is checked against, and what
		// is emitted when the provider has no opinion of its own. A provider that narrows by editing what it
		// was given - which is how narrowing is written throughout this repository - would otherwise move the
		// yardstick it is being measured by, and an emptied request reads exactly like one that never asked.
		var requestedDetails = request.AuthorizationDetails is { } asRequested
			? (JsonArray)asRequested.DeepClone()
			: null;

		// The response types this request was validated for, read the same way and for the same reason:
		// they decide which builders run, and the loop that reads them runs long after the provider held
		// the request.
		string[]? responseType = request.Model.ResponseType is { } asValidated
			? [..asValidated]
			: null;

		// Retrieve user consents (i.e., permissions granted for requested
		// scopes/resources/authorization_details), as prompt=consent leaves them
		var userConsents = await _consentsReader.ReadAsync(request, authSession);

		if (ConsentStillOwed(request, authSession, userConsents) is { } consentAnswer)
			return consentAnswer;

		// A consent the end user gave that grants nothing of what was asked is their refusal, which OpenID Connect
		// Core 1.0, section 3.1.2.6, tells the client with access_denied ("If the End-User denies the request ...")
		if (IsRefusal(request, userConsents, requestedDetails))
		{
			return new AuthorizationError(
				model,
				ErrorCodes.AccessDenied,
				"The end-user refused consent.",
				request.ResponseMode,
				model.RedirectUri);
		}

		// RFC 9396 section 7.1: "The authorization details attached to the access token MAY differ from what
		// the client requests", the user authorizing less than was asked being the named case. section 7 is what
		// obliges the server to tell the client what it actually got.
		//   Granted.AuthorizationDetails == null    -> legacy provider, no AD opinion; pass through what the
		//                                              validator pipeline produced (backward compat with PR #135).
		//   Granted.AuthorizationDetails is { Count: 0 } AND the request carried AD entries
		//                                           -> user denied every entry; fail with access_denied.
		//   Granted.AuthorizationDetails is non-empty -> explicit consent (possibly narrowed); emit as-is.
		if (userConsents.Granted.AuthorizationDetails is { Count: 0 }
			&& requestedDetails is { Count: > 0 })
		{
			return new AuthorizationError(
				model,
				ErrorCodes.AccessDenied,
				"The end-user denied consent for all requested authorization_details entries.",
				request.ResponseMode,
				model.RedirectUri);
		}

		var authContext = await BuildAuthorizationContextAsync(request, userConsents, requestedDetails);
		return await IssueAsync(request, authSession, authContext, responseType);
	}

	/// <summary>
	/// Whether <paramref name="consents"/>, given by the end user, grant nothing of what the request asked for.
	/// </summary>
	/// <remarks>
	/// A request asking for nothing a consent could grant is never refused this way. Authorization details count only
	/// when the request asked for some: then a grant carrying none of them, as no list or as an empty one, grants
	/// nothing of them either. A grant holding a scope or a resource is no refusal, and its missing list passes the
	/// requested details through as the host having no opinion on them.
	/// </remarks>
	private static bool IsRefusal(ValidAuthorizationRequest request, UserConsents consents, JsonArray? requestedDetails)
	{
		var askedForDetails = requestedDetails is { Count: > 0 };
		var askedFor = request.Scope.Length > 0 || request.Resources.Length > 0 || askedForDetails;

		return askedFor &&
		       consents is { GivenAt: not null, Granted: { Scopes.Length: 0, Resources.Length: 0 } } &&
		       (!askedForDetails || consents.Granted.AuthorizationDetails is null or { Count: 0 });
	}

	/// <summary>
	/// The answer a request gets while consent for some of what it asks is still pending, or null when none is.
	/// </summary>
	private AuthorizationResponse? ConsentStillOwed(
		ValidAuthorizationRequest request,
		AuthSession authSession,
		UserConsents userConsents)
	{
		var model = request.Model;

		// If consent for required scopes, resources, or authorization_details is still pending, handle it.
		if (userConsents.Pending is { Scopes.Length: > 0 }
			or { Resources.Length: > 0 }
			or { AuthorizationDetails.Count: > 0 })
		{
			// If user interaction is disallowed but consent is necessary, return an error.
			if (PromptPages.Asks(model, Prompts.None))
			{
				return new AuthorizationError(
					model,
					ErrorCodes.ConsentRequired,
					"The Authorization Server requires End-User consent.",
					request.ResponseMode,
					model.RedirectUri);
			}

			// Prompt for consent if necessary permissions are not yet granted.
			// A request asking for consent is stamped, so the consent the host records on that page answers it
			var consentPage = PromptPages.Asks(model, Prompts.Consent)
				? PromptPages.Stamped(model, Prompts.Consent, clock.GetUtcNow())
				: model;
			return new ConsentRequired(consentPage, authSession, userConsents.Pending);
		}

		return null;
	}

	/// <summary>
	/// Builds the context the issued codes and tokens carry, from what the end user granted.
	/// </summary>
	private async Task<AuthorizationContext> BuildAuthorizationContextAsync(
		ValidAuthorizationRequest request,
		UserConsents userConsents,
		JsonArray? requestedDetails)
	{
		var model = request.Model;

		// Defense-in-depth backstop: the IUserConsentsProvider contract permits a NARROWER grant
		// than the request, never a broader one. Assert that invariant before the granted set
		// reaches the issued token. A violation is a host-side defect (a buggy consent provider, or
		// browser tampering it failed to intersect against the request), so it surfaces as an
		// exception rather than an escalated grant. Symmetric with the strictly narrowing-only
		// TokenAuthorizationContextEvaluator at the token endpoint.
		// What the end user granted, read before the backstop runs. It is a seam of its own and it is
		// handed the granted set to check, so the scopes and resources the token carries are taken from
		// the answer rather than from what the check left behind.
		ScopeDefinition[] grantedScopes = [..userConsents.Granted.Scopes];
		ResourceDefinition[] grantedResources = [..userConsents.Granted.Resources];

		// Handed what was asked for rather than what the provider left behind: the backstop measures the
		// granted set against the request, and the provider it is policing can reach that array.
		var enforcedAuthorizationDetails = await consentConstraintEnforcer.EnforceAsync(
			request with { AuthorizationDetails = requestedDetails },
			userConsents.Granted,
			CancellationToken.None);

		// C2 (PR #135 review): the JsonArray reference passed to the consent provider and the
		// one placed on AuthorizationContext travel through System.Text.Json on the way to the
		// issued JWT. If a host's IUserConsentsProvider impl parents the borrowed array as a
		// child of its own DTO, the second serialise will throw because the JsonNode is parented
		// twice. DeepClone defensively on the boundary so the two consumers each see independent
		// trees -- matches the DeepClone discipline applied elsewhere (ApplyTo, resolvers).
		var sourceAd = enforcedAuthorizationDetails ?? requestedDetails;
		var emittedAuthorizationDetails = sourceAd is { Count: > 0 }
			? (JsonArray?)sourceAd.DeepClone()
			: null;

		// Build an authorization context containing necessary data like client ID, scopes, and claims.
		// The authorization context is used to carry the granted scopes, resources and other key details through
		// the flow.
		return new AuthorizationContext(
			request.ClientInfo.ClientId,
			grantedScopes,
			grantedResources,
			model.Claims)
		{
			RedirectUri = model.RedirectUri,
			Nonce = model.Nonce,
			// An empty code_challenge, which a request object carries as written, is no challenge: PkceValidator
			// treats it as absent, and so does the code exchange
			CodeChallenge = model.CodeChallenge.HasValue() ? model.CodeChallenge : null,
			CodeChallengeMethod = model.CodeChallengeMethod,
			ProofKeyThumbprint = model.ProofKeyThumbprint,
			AuthorizationDetails = emittedAuthorizationDetails,
		};
	}

	/// <summary>
	/// Records the client for the session and issues what each requested response type asks for.
	/// </summary>
	private async Task<AuthorizationResponse> IssueAsync(
		ValidAuthorizationRequest request,
		AuthSession authSession,
		AuthorizationContext authContext,
		string[]? responseType)
	{
		// Recorded before anything is issued, so a store that refuses the record fails the authorization
		// rather than following a code or a token already handed out.
		await sessionClients.AddClientAsync(authSession.SessionId, request.ClientInfo.ClientId);

		// Initialize a successful authentication result. GrantedScopes carries the consent-narrowed
		// scope set (identical to what the issued token carries) so the response encoder advertises the
		// granted scope on the front-channel scope parameter, not the broader requested set (RFC 6749 section 3.3)
		var result = new SuccessfullyAuthenticated(
			request.Model,
			request.ResponseMode,
			authSession.SessionId,
			[..await sessionClients.GetClientsAsync(authSession.SessionId)])
		{
			GrantedScopes = authContext.Scope,
		};

		var authorizedGrant = new AuthorizedGrant(authSession, authContext);

		// Dispatch each requested response-type part to its registered builder. The DI
		// registration order - AuthorizationCodeBuilder in the core registration, then
		// TokenResponseBuilder and IdTokenResponseBuilder added by EnableImplicitFlow -
		// preserves the dependency IdTokenResponseBuilder has on the code and access-token
		// fields populated by earlier builders (used to compute c_hash / at_hash). Parts
		// whose builders are not registered (e.g. token / id_token when Implicit Flow is not
		// enabled) cannot reach this point: FlowTypeValidator rejects the request earlier
		// with unsupported_response_type.
		foreach (var processor in responseProcessors)
		{
			if (!responseType.HasFlag(processor.ResponseType))
				continue;

			await processor.BuildResponseAsync(request, authorizedGrant, result);
		}

		// Return the final authorization result containing codes and tokens as needed.
		return result;
	}
}
