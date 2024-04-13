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
	public async Task<EndSessionResponse> ProcessAsync(ValidEndSessionRequest request)
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
			return new EndSessionSuccessfulResponse(postLogoutRedirectUri, Array.Empty<Uri>());
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

		var response = new EndSessionSuccessfulResponse(postLogoutRedirectUri, context.FrontChannelLogoutRequestUris);
		return response;
	}

	private static class Parameters
	{
		public const string State = "state";
	}
}
