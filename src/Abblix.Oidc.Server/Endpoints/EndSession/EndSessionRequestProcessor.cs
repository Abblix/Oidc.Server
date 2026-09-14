// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;


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
/// <param name="sessionLogoutNotifier">Notifies the clients of the ended session.</param>
/// <param name="tokenRevoker">Revokes the tokens of the ended session, when the deployment asks for it.</param>
/// <param name="options">Supplies whether ending a session revokes its tokens.</param>
public partial class EndSessionRequestProcessor(
	ILogger<EndSessionRequestProcessor> logger,
	IAuthSessionService authSessionService,
	ISessionLogoutNotifier sessionLogoutNotifier,
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

		var context = await sessionLogoutNotifier.NotifyClientsAsync(sessionId, subjectId);

		var response = new EndSessionSuccess(postLogoutRedirectUri, context.FrontChannelLogoutRequestUris);
		return response;
	}
}
