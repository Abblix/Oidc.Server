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
public class BackChannelAuthenticationRequestProcessor(
	IBackChannelRequestStorage storage,
	IOptionsSnapshot<OidcOptions> options,
	IUserDeviceAuthenticationHandler userDeviceAuthenticationHandler,
	TimeProvider timeProvider) : IBackChannelAuthenticationRequestProcessor
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

		var authorizedGrant = new AuthorizedGrant(authResult.GetSuccess(), authContext);

		var pollingInterval = options.Value.BackChannelAuthentication.PollingInterval;

		// Store authentication request with notification endpoint and token (used by ping and push modes)
		var expiresAt = timeProvider.GetUtcNow() + request.ExpiresIn;

		var backChannelRequest = new BackChannelAuthenticationRequest(authorizedGrant, expiresAt)
		{
			Status = BackChannelAuthenticationStatus.Pending,

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
}
