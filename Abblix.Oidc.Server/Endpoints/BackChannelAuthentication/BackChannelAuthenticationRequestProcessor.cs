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
	/// a <see cref="Result{BackChannelAuthenticationSuccess, BackChannelAuthenticationError}"/>.</returns>
	public async Task<Result<BackChannelAuthenticationSuccess, BackChannelAuthenticationError>> ProcessAsync(ValidBackChannelAuthenticationRequest request)
	{
		request.ClientInfo.CheckClientLicense();

		var authResult = await _userDeviceAuthenticationHandler.InitiateAuthenticationAsync(request);

		AuthorizedGrant authorizedGrant;
		if (authResult.TryGetSuccess(out var authSession))
		{
			var authContext = new AuthorizationContext(
				request.ClientInfo.ClientId,
				request.Scope,
				request.Resources,
				request.Model.Claims);

			authorizedGrant = new AuthorizedGrant(authSession, authContext);
		}
		else if (authResult.TryGetFailure(out var error))
		{
			return error.ErrorCode switch
			{
				ErrorCodes.UnauthorizedClient => new BackChannelAuthenticationUnauthorized(ErrorCodes.AccessDenied, error.ErrorDescription),
				ErrorCodes.AccessDenied => new BackChannelAuthenticationForbidden(ErrorCodes.AccessDenied, error.ErrorDescription),
				_ => new BackChannelAuthenticationError(error.ErrorCode, error.ErrorDescription)
			};
		}
		else
		{
			throw new InvalidOperationException("Unexpected result state");
		}

		var pollingInterval = _options.Value.BackChannelAuthentication.PollingInterval;

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
