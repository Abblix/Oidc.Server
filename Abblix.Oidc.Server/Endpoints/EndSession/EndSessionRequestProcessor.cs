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

using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.Logging;


namespace Abblix.Oidc.Server.Endpoints.EndSession;

/// <summary>
/// Implements the logic for processing end-session requests.
/// </summary>
/// <remarks>
/// This class is responsible for handling end-session requests. It facilitates user logout, client notifications,
/// and ensures compliance with the relevant OAuth 2.0 and OpenID Connect standards.
/// </remarks>
public class EndSessionRequestProcessor : IEndSessionRequestProcessor
{
	/// <summary>
	/// Initializes a new instance of the <see cref="EndSessionRequestProcessor"/> class.
	/// </summary>
	/// <param name="logger">The logger.</param>
	/// <param name="authSessionService">The authentication service.</param>
	/// <param name="issuerProvider">The issuer provider.</param>
	/// <param name="clientInfoProvider">The client info provider.</param>
	/// <param name="logoutNotifier">The logout notifier.</param>
	public EndSessionRequestProcessor(
		ILogger<EndSessionRequestProcessor> logger,
		IAuthSessionService authSessionService,
		IIssuerProvider issuerProvider,
		IClientInfoProvider clientInfoProvider,
		ILogoutNotifier logoutNotifier)
	{
		_logger = logger;
		_authSessionService = authSessionService;
		_issuerProvider = issuerProvider;
		_clientInfoProvider = clientInfoProvider;
		_logoutNotifier = logoutNotifier;
	}

	private readonly ILogger _logger;
	private readonly IAuthSessionService _authSessionService;
	private readonly IClientInfoProvider _clientInfoProvider;
	private readonly IIssuerProvider _issuerProvider;
	private readonly ILogoutNotifier _logoutNotifier;

	/// <summary>
	/// Processes the end-session request and returns the corresponding response.
	/// </summary>
	/// <param name="request">The valid end-session request to be processed.</param>
	/// <returns>A task representing the asynchronous operation, which upon completion will yield the <see cref="EndSessionResponse"/>.</returns>
	public async Task<Result<EndSessionSuccess, EndSessionError>> ProcessAsync(ValidEndSessionRequest request)
	{
		var postLogoutRedirectUri = request.Model.PostLogoutRedirectUri;
		if (postLogoutRedirectUri != null && request.Model.State != null)
		{
			postLogoutRedirectUri = new UriBuilder(postLogoutRedirectUri)
			{
				Query =
				{
					[Parameters.State] = request.Model.State,
				}
			};
		}

		var authSession = await _authSessionService.AuthenticateAsync();
		if (authSession == null)
		{
			return new EndSessionSuccess(postLogoutRedirectUri, Array.Empty<Uri>());
		}

		var sessionId = authSession.SessionId;

		var subjectId = authSession.Subject;
		if (!subjectId.HasValue())
		{
			throw new InvalidOperationException(
				$"The claim {JwtClaimTypes.Subject} must contain the unique identifier of the user logged in");
		}

		await _authSessionService.SignOutAsync();
		_logger.LogDebug("The user with subject={Subject} was logged out from session {Session}", subjectId, sessionId);

		var context = new LogoutContext(sessionId, subjectId, LicenseChecker.CheckIssuer(_issuerProvider.GetIssuer()));

		var tasks = new List<Task>();
		foreach (var clientId in authSession.AffectedClientIds)
		{
			var clientInfo = await _clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
			if (clientInfo == null)
				continue;

			var task = _logoutNotifier.NotifyClientAsync(clientInfo, context);
			if (task.Status == TaskStatus.Running)
				tasks.Add(task);
		}
		await Task.WhenAll(tasks);

		var response = new EndSessionSuccess(postLogoutRedirectUri, context.FrontChannelLogoutRequestUris);
		return response;
	}

	private static class Parameters
	{
		public const string State = "state";
	}
}
