// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
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
/// <param name="logger">The logger.</param>
/// <param name="authSessionService">The authentication service.</param>
/// <param name="issuerProvider">The issuer provider.</param>
/// <param name="clientInfoProvider">The client info provider.</param>
/// <param name="logoutNotifier">The logout notifier.</param>
/// <param name="tokenRevoker">Revokes the tokens of the ended session, when the deployment asks for it.</param>
/// <param name="options">Supplies whether ending a session revokes its tokens.</param>
public partial class EndSessionRequestProcessor(
	ILogger<EndSessionRequestProcessor> logger,
	IAuthSessionService authSessionService,
	IIssuerProvider issuerProvider,
	IClientInfoProvider clientInfoProvider,
	ILogoutNotifier logoutNotifier,
	ITokenRevoker tokenRevoker,
	IOptions<OidcOptions> options) : IEndSessionRequestProcessor
{
	/// <summary>
	/// Processes the end-session request and returns the corresponding response.
	/// </summary>
	/// <param name="request">The valid end-session request to be processed.</param>
	/// <returns>A task representing the asynchronous operation, which upon completion will yield an
	/// <see cref="EndSessionSuccess"/> or an <see cref="OidcError"/>.</returns>
	public async Task<Result<EndSessionSuccess, OidcError>> ProcessAsync(ValidEndSessionRequest request)
	{
		var postLogoutRedirectUri = request.Model.PostLogoutRedirectUri;
		if (postLogoutRedirectUri != null && request.Model.State != null)
		{
			postLogoutRedirectUri = new UriBuilder(postLogoutRedirectUri)
			{
				Query =
				{
					[EndSessionRequest.Parameters.State] = request.Model.State,
				}
			};
		}

		var authSession = await authSessionService.AuthenticateAsync();
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

		await authSessionService.SignOutAsync();

		// Recorded before any client is told, so a client acting on the notification cannot refresh its way
		// back in against a cutoff that has not been written yet.
		if (options.Value.RevokeSessionTokensOnLogout)
			await tokenRevoker.RevokeSessionAsync(sessionId);

		LogUserLoggedOut(subjectId, sessionId);

		var context = new LogoutContext(sessionId, subjectId, LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()));

		// Await every logout notification so the back-channel POST is actually sent. An earlier
		// `task.Status == Running` filter silently dropped these tasks (an async notifier's task is
		// WaitingForActivation, not Running), leaving the POST detached and abandoned at request end.
		// Notification is best-effort: NotifyClientSafelyAsync isolates per-client failures so an
		// unreachable client endpoint cannot fail the end-user's logout.
		var tasks = new List<Task>();
		foreach (var clientId in authSession.AffectedClientIds)
		{
			var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
			if (clientInfo == null)
				continue;

			tasks.Add(NotifyClientSafelyAsync(clientInfo, context));
		}
		await Task.WhenAll(tasks);

		var response = new EndSessionSuccess(postLogoutRedirectUri, context.FrontChannelLogoutRequestUris);
		return response;
	}

	/// <summary>
	/// Notifies a single client of the logout, isolating any failure. Back-channel and front-channel
	/// logout are best-effort: a client whose endpoint is unreachable (down, TLS failure, blocked) is
	/// logged for operator attention but must not fail the end-user's logout.
	/// </summary>
	private async Task NotifyClientSafelyAsync(ClientInfo clientInfo, LogoutContext context)
	{
		try
		{
			await logoutNotifier.NotifyClientAsync(clientInfo, context);
		}
		catch (Exception exception)
		{
			LogClientLogoutNotificationFailed(exception, clientInfo.ClientId);
		}
	}

}
