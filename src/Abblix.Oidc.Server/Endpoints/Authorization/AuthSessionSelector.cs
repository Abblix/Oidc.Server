// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using AuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Decides which signed-in session answers an authorization request, or which interaction or error has to
/// answer it first: the end user logging in, creating an account or choosing among several sessions.
/// </summary>
internal sealed class AuthSessionSelector(
	IAuthSessionService authSessionService,
	IRevocationCutoffChecker cutoffChecker,
	ISubjectTypeConverter subjectTypeConverter,
	TimeProvider clock)
{
	/// <summary>
	/// The values of <c>prompt</c> whose pages a session answers, in the order the pages come: account creation or
	/// account selection, then authentication. Consent is asked after a session is chosen.
	/// </summary>
	private static readonly string[] SessionPrompts = [Prompts.Create, Prompts.SelectAccount, Prompts.Login];

	/// <summary>
	/// Selects the session the request proceeds with.
	/// </summary>
	/// <param name="request">The validated authorization request.</param>
	/// <returns>The single session to authorize with, or the response that answers the request instead.</returns>
	public async Task<Result<AuthSession, AuthorizationResponse>> SelectAsync(ValidAuthorizationRequest request)
	{
		// Retrieves any available user authentication sessions, filtered by the request's parameters.
		var (authSessions, authenticationLevelUnmet, hostHoldsAny) = await GetAvailableAuthSessionsAsync(request);

		var (prompt, sessionsAnswering) = PromptStillAsked(request.Model, authSessions);
		return Choose(request, sessionsAnswering, prompt, authenticationLevelUnmet, hostHoldsNone: !hostHoldsAny);
	}

	/// <summary>
	/// Answers the request by the number of sessions left to it and the prompt it still asks for.
	/// </summary>
	private Result<AuthSession, AuthorizationResponse> Choose(
		ValidAuthorizationRequest request,
		List<AuthSession> authSessions,
		string? prompt,
		bool authenticationLevelUnmet,
		bool hostHoldsNone)
	{
		var model = request.Model;
		switch (authSessions.Count, prompt)
		{
			// Initiating User Registration via OpenID Connect 1.0: prompt=create takes the user to
			// the account-creation experience regardless of whether a session exists. An OP that
			// advertises create in prompt_values_supported must act on it. Without its own arm the
			// value falls through to the generic branches and the registration intent is lost.
			case (_, Prompts.Create):
				return new RegistrationRequired(PromptPages.Stamped(model, Prompts.Create, clock.GetUtcNow()));

			// A request requiring an authentication level, forbidding interaction and left with no session is
			// the failed authentication attempt section 5.5.1.1 demands, and the OpenID Foundation gives it a
			// code of its own: unmet_authentication_requirements "SHALL be used if the Relying Party wants the
			// OP to conform to a certain Authentication Context Class Reference value using an essential claim
			// acr claim ... and the OP is unable to meet this requirement". Saying login_required instead would
			// send the client to retry an interaction that cannot change the answer.
			case (0, Prompts.None) when authenticationLevelUnmet:
				return new AuthorizationError(
					model,
					ErrorCodes.UnmetAuthenticationRequirements,
					"The authentication the request requires could not be performed.",
					request.ResponseMode,
					model.RedirectUri);

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

			// The request asks the end user to choose an account. With no session at all, the page is where they reach
			// an account they are not signed in to yet; a session the request's filters left out goes to the login
			// page below instead, since choosing it again could not get it past them.
			case (> 0, Prompts.SelectAccount):
			case (0, Prompts.SelectAccount) when hostHoldsNone:
				return SendToAccountSelection(model, authSessions);

			// If no sessions exist, or the request explicitly asks for a login, prompt the user for login.
			case (0, _) or (_, Prompts.Login):
				return SendToLogin(model);

			// If multiple sessions exist, prompt the user to select an account. Sessions that all answered an earlier
			// selection page are asked again under a new stamp, so the next pick narrows them.
			case (> 1, _):
				return PromptPages.Asks(model, Prompts.SelectAccount)
					? SendToAccountSelection(model, authSessions)
					: new AccountSelectionRequired(model, authSessions.ToArray());

			// If a single session exists, proceed with that session for further processing.
			case (1, _):
				return authSessions.Single();

			// Catch any unexpected cases where the session count or prompt state
			// does not match the expected conditions.
			default:
				throw new InvalidOperationException(
					$"Unexpected number of auth sessions: {authSessions.Count} or prompt: {prompt}");
		}
	}

	/// <summary>
	/// Sends the end user to choose an account, stamping the request with the moment, so the request coming back with
	/// a session signed in since is not sent there again.
	/// </summary>
	private AccountSelectionRequired SendToAccountSelection(Model.AuthorizationRequest model, List<AuthSession> authSessions)
	{
		var now = clock.GetUtcNow();
		var stamped = PromptPages.Stamped(model, Prompts.SelectAccount, now);

		// An end user authenticating on the selection page answers a login the request also asks for, so they are not
		// sent to authenticate twice; picking a session authenticated earlier still leaves the login page to come
		if (PromptPages.Asks(model, Prompts.Login) && model.Prompted?.ContainsKey(Prompts.Login) is not true)
			stamped = PromptPages.Stamped(stamped, Prompts.Login, now);

		return new AccountSelectionRequired(stamped, authSessions.ToArray());
	}

	/// <summary>
	/// Sends the end user to log in, stamping the request for the login it asks, so the request coming back with a
	/// session authenticated since is not sent there again.
	/// </summary>
	/// <remarks>
	/// An account selection the request also asks for is not stamped here: a login page may sign the end user in
	/// without asking anything, as a request not asking for login lets it, and the account it signs in to is not one
	/// the end user chose. The selection page follows.
	/// </remarks>
	private LoginRequired SendToLogin(Model.AuthorizationRequest model)
		=> new(PromptPages.Asks(model, Prompts.Login) ? PromptPages.Stamped(model, Prompts.Login, clock.GetUtcNow()) : model);

	/// <summary>
	/// The prompt the request still asks this selection for, and the sessions that may answer the request.
	/// </summary>
	/// <remarks>
	/// The request comes back from each page still carrying its prompt, and asking again would send the end user round
	/// in a loop. The pages come in the server's order whatever order the client wrote: account creation or selection,
	/// then authentication; consent is asked after a session is chosen. Each is answered by a session the host wrote
	/// since the server sent the end user there, and the request proceeds with those sessions alone. A new account
	/// answers selection and authentication alike, so nothing after it is asked.
	/// </remarks>
	private static (string? Prompt, List<AuthSession> Sessions) PromptStillAsked(
		Model.AuthorizationRequest model,
		List<AuthSession> authSessions)
	{
		if (PromptPages.Asks(model, Prompts.None))
			return (Prompts.None, authSessions);

		foreach (var prompt in SessionPrompts)
		{
			if (!PromptPages.Asks(model, prompt))
				continue;

			var answering = authSessions
				.Where(session => PromptPages.AnsweredBy(model, prompt, AnswerOf(prompt, session)))
				.ToList();
			if (answering.Count == 0)
				return (prompt, authSessions);

			authSessions = answering;
			if (prompt == Prompts.Create)
				break;
		}

		return (null, authSessions);
	}

	/// <summary>
	/// The moment <paramref name="session"/> was written in a way that answers the page of <paramref name="prompt"/>:
	/// authenticated for an account created or a login, signed in for an account chosen.
	/// </summary>
	private static DateTimeOffset? AnswerOf(string prompt, AuthSession session) => prompt switch
	{
		Prompts.Create or Prompts.Login => session.AuthenticationTime,
		Prompts.SelectAccount => session.SignedInAt,
		_ => throw new ArgumentOutOfRangeException(nameof(prompt), prompt, "No session answers this prompt"),
	};

	/// <summary>
	/// Retrieves the available authentication sessions based on the request's constraints (e.g., max age, ACR values).
	/// This function ensures that only sessions meeting the request's criteria (e.g., recency, security level)
	/// are used.
	/// </summary>
	/// <param name="request">The validated request: its model supplies max age and ACR values, its client
	/// the default_max_age and default_acr_values fallbacks, and it carries the end user an
	/// <c>id_token_hint</c> named.</param>
	/// <returns>The sessions matching the request's criteria; whether an authentication level the request required is
	/// what left none of them, which is a different answer to the client than having nobody signed in; and whether the
	/// host held any session before the filters, which tells a session the filters left out from none at all.</returns>
	private async ValueTask<(List<AuthSession> Sessions, bool AuthenticationLevelUnmet, bool HostHoldsAny)>
		GetAvailableAuthSessionsAsync(ValidAuthorizationRequest request)
	{
		var model = request.Model;
		var clientInfo = request.ClientInfo;

		// Read once, so whether the host held any session before the filters below is known without asking it again
		var heldByHost = new List<AuthSession>();
		await foreach (var session in authSessionService.GetAvailableAuthSessions())
			heldByHost.Add(session);

		IEnumerable<AuthSession> authSessions = heldByHost;

		// Filter by maximum authentication age. When the request omits max_age, fall back to the
		// client's registered default_max_age (OIDC Core section 2 / section 3.1.2.1).
		var maxAge = model.MaxAge ?? clientInfo.DefaultMaxAge;
		if (maxAge.HasValue)
		{
			// skip all sessions older than the effective max_age value
			var minAuthenticationTime = clock.GetUtcNow() - maxAge;
			authSessions = authSessions.Where(session => minAuthenticationTime < session.AuthenticationTime);
		}

		// Filter by required ACR values. When the request omits acr_values, fall back to the client's
		// registered default_acr_values (OIDC Core section 2).
		var acrValues = model.AcrValues is { Length: > 0 } requestedAcrValues
			? requestedAcrValues
			: clientInfo.DefaultAcrValues;
		if (acrValues is { Length: > 0 })
		{
			authSessions = authSessions.Where(
				session => AuthenticationLevels.Accept(acrValues, session.AuthContextClassRef));
		}

		// OpenID Connect Core 1.0 Sections 3.1.2.1 and 3.1.2.2: when a request names an end user, a
		// positive response is owed only if that end user is the one logged in, and otherwise the server
		// MUST return an error. Comparing here rather than refusing outright is what serves the whole
		// sentence: a request left with no session takes the arms above, so prompt=none answers
		// login_required while anything else reaches the login page, which is where "is logged in as a
		// result of the request" happens.
		//
		// A request requiring an authentication level takes one more arm: where that requirement is what
		// left no session, the refusal names it rather than saying login_required.
		//
		// That last part is the host's to finish, and it is worth saying because the failure is a loop
		// rather than an error: a login page that returns the session it already has, without prompting,
		// arrives back here to be filtered out again. The same is true of max_age and acr_values, and a
		// host handling those already has the shape. What it needs from the request is the named end user,
		// which the model carries verbatim.
		//
		// Two parameters name one, independently, and Section 3.1.2.2 puts them under a single MUST, so a
		// request stating both has both applied. They are separate filters rather than a merged set of
		// acceptable subjects, because merging would have to decide what an id_token_hint disagreeing with
		// a claims request means - and nothing has to decide that if each simply binds.
		if (request.IdTokenHintSubject is { } hinted)
			authSessions = authSessions.Where(
				session => subjectTypeConverter.Names(session, [hinted], clientInfo));

		if (request.RequestedSubjects is { } requested)
			authSessions = authSessions.Where(
				session => subjectTypeConverter.Names(session, requested, clientInfo));

		// A revocation reaches the session as well as the tokens, and it has to be read here because
		// everything below mints against whichever session survives, stamping a fresh iat that no
		// token-side cutoff can catch. This closes the repeatable door; the token endpoint closes the
		// other one, where a grant authorized earlier is redeemed after the revocation. Read after the
		// cheap filters above, so a session already ruled out by max_age, acr or the hint costs no store
		// lookup.
		var candidates = await KeepUnrevokedAsync(authSessions);

		// An essential acr naming acceptable values is the same question acr_values asks, with an obligation
		// attached: section 5.5.1.1 says the server "MUST return an acr Claim Value that matches one of the
		// requested values", and that an outcome which cannot meet it is "a failed authentication attempt".
		// Filtering rather than refusing takes the latitude the same sentence grants - it "MAY ask the
		// End-User to re-authenticate with additional factors" - so a request no current session satisfies
		// reaches the login page. A session recording no level is dropped exactly as acr_values drops it: an
		// absent level meets no named one.
		//
		// Last, and over the materialised list, because the endpoint has to tell what THIS requirement
		// removed from what every other filter removed. Answering the dedicated error code off the final
		// count would report an unmet authentication level to a request that has none signed in at all, or
		// one whose session holds exactly the level asked for and was dropped by max_age - and in both of
		// those, interaction is what changes the answer, which is what login_required tells the client to
		// try.
		if (request.RequiredAuthContextClassRefs is not { Length: > 0 } requiredAcrValues)
			return (candidates, false, heldByHost.Count > 0);

		var atRequiredLevel = candidates.FindAll(
			session => AuthenticationLevels.Accept(requiredAcrValues, session.AuthContextClassRef));

		return (atRequiredLevel, candidates.Count > 0 && atRequiredLevel.Count == 0, heldByHost.Count > 0);
	}

	/// <summary>
	/// Drops the sessions a revocation cutoff refuses, keeping the order of the rest.
	/// </summary>
	/// <remarks>
	/// A request left with no session takes the arms above, so <c>prompt=none</c> answers
	/// <c>login_required</c>, which OpenID Connect Core 1.0 Section 3.1.2.6 defines as "The Authorization
	/// Server requires End-User authentication. This error MAY be returned when the prompt parameter value
	/// in the Authentication Request is none, but the Authentication Request cannot be completed without
	/// displaying a user interface for End-User authentication." Any other request reaches the login page.
	/// </remarks>
	/// <remarks>
	/// A dropped session is ignored rather than signed out. Signing out would be the tidier outcome for the
	/// one adapter this library ships, where the session being judged is the requester's own cookie; it is
	/// wrong for an adapter holding several, where the session dropped need not be the one whose cookie the
	/// response would clear. Ignoring is correct for both, at the price of judging the same session again on
	/// the next request - two store reads per candidate, since a cutoff can be recorded against either the
	/// subject or the session and the common answer is that neither exists.
	///
	/// What that leaves behind is a browser-state cookie the provider no longer honours, so a relying party
	/// polling check_session sees no change and does not learn the session ended. It corrects itself on the
	/// next successful sign-in, which rewrites the cookie; until then the two views disagree.
	/// </remarks>
	private async ValueTask<List<AuthSession>> KeepUnrevokedAsync(IEnumerable<AuthSession> sessions)
	{
		var kept = new List<AuthSession>();
		foreach (var session in sessions)
		{
			if (!await cutoffChecker.IsSessionRefusedAsync(session))
				kept.Add(session);
		}

		return kept;
	}
}
