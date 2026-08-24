// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;


namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;

/// <summary>
/// Handles the processing of backchannel authentication requests in an OAuth 2.0/OpenID Connect context.
/// This class is responsible for managing the lifecycle of a backchannel authentication request,
/// from initiating the user's authentication on their device to storing the request for status polling.
/// It ensures that the client is authorized, user-device authentication is initiated, and the request's status
/// is properly stored and can be queried during the authentication process.
/// The class coordinates various services like authentication storage, options configuration and user-device
/// interaction, ensuring a seamless backchannel authentication flow.
/// </summary>
/// <param name="storage">Service for storing and retrieving backchannel authentication requests.</param>
/// <param name="options">Configuration options related to backchannel authentication.</param>
/// <param name="userDeviceAuthenticationHandler">Handler for initiating authentication on the user's device.</param>
/// <param name="timeProvider">Time provider for managing authentication request expiration.</param>
/// <param name="subjectTypeConverter">
/// Seals a session's subject the way the requesting client sees it, so the session the host authenticated can
/// be compared against the end user an <c>id_token_hint</c> named.
/// </param>
public class BackChannelAuthenticationRequestProcessor(
	IBackChannelRequestStorage storage,
	IOptionsSnapshot<OidcOptions> options,
	IUserDeviceAuthenticationHandler userDeviceAuthenticationHandler,
	TimeProvider timeProvider,
	ISubjectTypeConverter subjectTypeConverter) : IBackChannelAuthenticationRequestProcessor
{
	/// <inheritdoc />
	/// <summary>
	/// Orchestrates the processing of a valid backchannel authentication request.
	/// This method coordinates between client validation, initiating user-device authentication,
	/// and persisting the authentication request for further polling.
	/// </summary>
	/// <param name="request">
	/// The validated backchannel authentication request containing details such as client info, scope, and resources.
	/// </param>
	/// <returns>A task that represents the result of processing the backchannel authentication request, returning
	/// a <see cref="Result{BackChannelAuthenticationSuccess, AuthError}"/>.</returns>
	public async Task<Result<BackChannelAuthenticationSuccess, OidcError>> ProcessAsync(ValidBackChannelAuthenticationRequest request)
	{
		request.ClientInfo.CheckClientLicense();

		var authResult = await userDeviceAuthenticationHandler.InitiateAuthenticationAsync(request);
		if (authResult.TryGetFailure(out var error))
		{
			return error.Error switch
			{
				ErrorCodes.UnauthorizedClient
					=> new BackChannelAuthenticationUnauthorized(ErrorCodes.AccessDenied, error.ErrorDescription),

				ErrorCodes.AccessDenied
					=> new BackChannelAuthenticationForbidden(ErrorCodes.AccessDenied, error.ErrorDescription),

				_ => error,
			};
		}

		var authSession = authResult.GetSuccess();

		// The host decides who approved on the device, and a request carrying an id_token_hint already said
		// who it means. OpenID Connect Core 1.0 Section 3.1.2.2: the server "MUST NOT reply with an ID Token
		// or Access Token for a different user, even if they have an active session with the Authorization
		// Server". Nothing in a device flow lets this server observe who picked up the phone, so a host
		// routing the notification to the wrong contact - stale details, a shared device, the wrong claim
		// used to look somebody up - would otherwise have tokens minted for whoever answered and handed to a
		// client that asked about someone else.
		//
		// The comparison belongs to the server rather than the host, because a host cannot perform it: the
		// hint carries the pseudonym this client sees, and sealing a session to compare against it needs the
		// pairwise settings. The same comparison serves the authorization endpoint.
		// Two parameters can name an end user and OpenID Connect Core 1.0 Section 3.1.2.2 puts both under one
		// requirement, so both bind. Their intersection is what survives, which is the same answer the
		// authorization endpoint reaches by filtering candidate sessions through one and then the other.
		var namedSubjects = NamedSubjects(request);

		// Answered now, because the session a handler returns here names the end user it is about to reach,
		// not one who has already answered - the request is stored Pending either way. A handler intending
		// to reach somebody else is refused before any notification goes out. The end user who eventually
		// answers is judged separately, at completion, against what is carried on the stored request.
		if (namedSubjects is { } accepted &&
			!subjectTypeConverter.Names(authSession, accepted, request.ClientInfo))
		{
			// CIBA Core 1.0 Section 13 defines access_denied as "The resource owner or OpenID Provider
			// denied the request", and it is this server denying it. The note attached there describes the
			// case authors expected - a standing decision to refuse a kind of request, since the response
			// normally precedes any user interaction - rather than bounding when the code may be used.
			// unknown_user_id, the other candidate, says the provider cannot identify the end user from the
			// hint, which is the opposite of what happened: it identified them and somebody else answered.
			return new BackChannelAuthenticationForbidden(
				ErrorCodes.AccessDenied,
				"The authenticated end user is not the one the request named");
		}

		var authContext = new AuthorizationContext(
			request.ClientInfo.ClientId,
			request.Scope,
			request.Resources,
			request.Model.Claims)
		{
			// RFC 9396 §3: authorization_details from the CIBA request carries onto the
			// grant byte-exact, so the access token issued via the CIBA grant emits the
			// claim through the same pipeline as the authorization-code flow.
			AuthorizationDetails = request.AuthorizationDetails,
		};

		var authorizedGrant = new AuthorizedGrant(authSession, authContext);

		var pollingInterval = options.Value.BackChannelAuthentication.PollingInterval;

		// Store authentication request with notification endpoint and token (used by ping and push modes)
		var expiresAt = timeProvider.GetUtcNow() + request.ExpiresIn;

		var backChannelRequest = new BackChannelAuthenticationRequest(authorizedGrant, expiresAt)
		{
			Status = BackChannelAuthenticationStatus.Pending,

			// Carried so the completion path can judge whoever eventually answers against what the request
			// asked for. Recorded even when the check above already passed: a host may replace the session
			// on the stored request before completing it, which is the shape the interface documents.
			RequestedSubjects = namedSubjects,

			// The client may poll from the moment it holds the request id, so the first allowed poll is
			// now, matching the device flow. CIBA section 11 adopts RFC 8628's polling rules, and section
			// 3.2 there defines the interval as the minimum to wait "between polling requests to the token
			// endpoint" - it has nothing to sit after until a first poll exists. This used to read
			// now + interval, which answered the first request with slow_down and cost every sign-in one
			// interval for polling too fast when nothing had been polled.
			NextPollAt = timeProvider.GetUtcNow(),

			ClientNotificationEndpoint = request.ClientInfo.BackChannelClientNotificationEndpoint,
			ClientNotificationToken = request.Model.ClientNotificationToken,
		};

		var authenticationRequestId = await storage.StoreAsync(backChannelRequest, request.ExpiresIn);

		return new BackChannelAuthenticationSuccess
		{
			AuthenticationRequestId = authenticationRequestId,
			ExpiresIn = request.ExpiresIn,
			Interval = pollingInterval,
		};
	}

	/// <summary>
	/// The end users this request will accept, by either parameter that can name one, or <c>null</c> when it
	/// named nobody in particular. An empty array accepts nobody.
	/// </summary>
	/// <remarks>
	/// OpenID Connect Core 1.0 Section 3.1.2.2 makes <c>id_token_hint</c> and a <c>claims</c> request for a
	/// specific <c>sub</c> two ways of stating one requirement, so a request carrying both states both, and
	/// what survives is their intersection - possibly nothing, which is the guaranteed mismatch Section 5.5.1
	/// already prescribes an outcome for.
	/// <para>
	/// A malformed <c>claims</c> qualifier cannot be reported from here, because this runs after the request
	/// was validated; the validator pipeline refuses one before anything reaches this method, so a failure
	/// arriving here would mean the pipeline had changed underneath it. Treated as naming nobody, which
	/// refuses rather than admits.
	/// </para>
	/// </remarks>
	private static string[]? NamedSubjects(ValidBackChannelAuthenticationRequest request)
	{
		var hinted = request.IdToken?.Payload.Subject is { Length: > 0 } named ? new[] { named } : null;

		var requested = request.Model.Claims.RequestedSubjects();
		var accepted = requested.TryGetSuccess(out var subjects) ? subjects : [];

		return (hinted, accepted) switch
		{
			(null, var only) => only,
			({ } one, null) => one,
			({ } one, { } many) => one.Intersect(many, StringComparer.Ordinal).ToArray(),
		};
	}
}
