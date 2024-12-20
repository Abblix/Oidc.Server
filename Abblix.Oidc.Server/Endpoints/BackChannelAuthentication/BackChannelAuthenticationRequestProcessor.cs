﻿// Abblix OIDC Server Library
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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
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
public class BackChannelAuthenticationRequestProcessor : IBackChannelAuthenticationRequestProcessor
{
	/// <summary>
	/// Initializes the processor with the necessary services required for handling backchannel authentication requests.
	/// This setup includes storage for persisting the authentication request state, configuration options
	/// and a handler for initiating user-device authentication.
	/// </summary>
	/// <param name="storage">Service for storing and retrieving backchannel authentication requests.</param>
	/// <param name="options">Configuration options related to backchannel authentication.</param>
	/// <param name="userDeviceAuthenticationHandler">Handler for initiating authentication on the user's device.
	/// </param>
	/// <param name="timeProvider"></param>
	public BackChannelAuthenticationRequestProcessor(
		IBackChannelAuthenticationStorage storage,
		IOptionsSnapshot<OidcOptions> options,
		IUserDeviceAuthenticationHandler userDeviceAuthenticationHandler,
		TimeProvider timeProvider)
	{
		_storage = storage;
		_options = options;
		_userDeviceAuthenticationHandler = userDeviceAuthenticationHandler;
		_timeProvider = timeProvider;
	}

	private readonly IBackChannelAuthenticationStorage _storage;
	private readonly IOptionsSnapshot<OidcOptions> _options;
	private readonly IUserDeviceAuthenticationHandler _userDeviceAuthenticationHandler;
	private readonly TimeProvider _timeProvider;

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
	/// the success response with a polling interval and expiry details.</returns>
	public async Task<BackChannelAuthenticationResponse> ProcessAsync(ValidBackChannelAuthenticationRequest request)
	{
		// Validate the client's license or eligibility for making the backchannel authentication request.
		request.ClientInfo.CheckClientLicense();

		AuthorizedGrant authorizedGrant;

		// Initiate the authentication flow on the user's device to retrieve the associated session
		var authResult = await _userDeviceAuthenticationHandler.InitiateAuthenticationAsync(request);
		switch (authResult)
		{
			case Result<AuthSession>.Success(var authSession):
				// Create the authorization context with details from the request
				var authContext = new AuthorizationContext(
					request.ClientInfo.ClientId,
					request.Scope,
					request.Resources,
					request.Model.Claims);

				authorizedGrant = new AuthorizedGrant(authSession, authContext);
				break;

			// Client authentication failed (e.g., invalid client credentials, unknown client,
			// no client authentication included, or unsupported authentication method)
			case Result<AuthSession>.Error(ErrorCodes.UnauthorizedClient, var description):
				return new BackChannelAuthenticationUnauthorized(ErrorCodes.AccessDenied, description);

			// The resource owner or OpenID Provider denied the request
			case Result<AuthSession>.Error(ErrorCodes.AccessDenied, var description):
				return new BackChannelAuthenticationForbidden(ErrorCodes.AccessDenied, description);

			// Return a generic error response for other issues
			case Result<AuthSession>.Error(var error, var description):
				return new BackChannelAuthenticationError(error, description);

			// Treat any unexpected results as exceptions
			default:
				throw new UnexpectedTypeException(nameof(authResult), authResult.GetType());
		}

		var pollingInterval = _options.Value.BackChannelAuthentication.PollingInterval;

		// Persist the backchannel authentication request with an initial pending status
		var authenticationRequestId = await _storage.StoreAsync(
			new BackChannelAuthenticationRequest(authorizedGrant)
			{
				Status = BackChannelAuthenticationStatus.Pending,
				NextPollAt = _timeProvider.GetUtcNow() + pollingInterval,
			},
			request.ExpiresIn);

		return new BackChannelAuthenticationSuccess
		{
			AuthenticationRequestId = authenticationRequestId,
			ExpiresIn = request.ExpiresIn,
			Interval = pollingInterval,
		};
	}
}
