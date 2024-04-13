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

using System.Security.Claims;
using System.Text.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using IAuthenticationService = Abblix.Oidc.Server.Features.UserAuthentication.IAuthenticationService;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Adapts ASP.NET Authentication Scheme to the <see cref="IAuthenticationService"/> interface.
/// Allows integration of Abblix Oidc Server with standard ASP.NET Authentication capability.
/// </summary>
public class AuthenticationSchemeAdapter : IAuthenticationService
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AuthenticationSchemeAdapter"/> class.
	/// </summary>
	/// <param name="httpContextAccessor">Provides access to the <see cref="HttpContext"/>.</param>
	public AuthenticationSchemeAdapter(IHttpContextAccessor httpContextAccessor)
	{
		_httpContextAccessor = httpContextAccessor;
	}

	private readonly IHttpContextAccessor _httpContextAccessor;

	private HttpContext HttpContext => _httpContextAccessor.HttpContext.NotNull(nameof(IHttpContextAccessor.HttpContext));

	/// <summary>
	/// Asynchronously retrieves the available authentication sessions for the current user.
	/// </summary>
	/// <returns>
	/// An asynchronous stream of <see cref="AuthSession"/> instances representing the current authentication sessions.
	/// </returns>
	public async IAsyncEnumerable<AuthSession> GetAvailableAuthSessions()
	{
		var user = await AuthenticateAsync();
		if (user != null)
		{
			yield return user;
		}
	}

	/// <summary>
	/// Asynchronously authenticates the current user based on the default authentication scheme.
	/// </summary>
	/// <returns>A task that represents the asynchronous operation.
	/// The task result contains the <see cref="AuthSession"/> of the authenticated user,
	/// or null if authentication fails.
	/// </returns>
	public async Task<AuthSession?> AuthenticateAsync()
	{
		var authenticationResult = await HttpContext.AuthenticateAsync();
		if (!authenticationResult.Succeeded)
			return null;

		var principal = authenticationResult.Principal;
		var properties = authenticationResult.Properties;

		var sessionId = properties.GetString(JwtClaimTypes.SessionId);
		if (string.IsNullOrEmpty(sessionId))
		{
			throw new InvalidOperationException(
				$"Use {nameof(SessionIdGenerator)}.{nameof(SessionIdGenerator.NewId)}() to generate a new session Id when calling .SignInAsync() method");
		}

		var authenticationTime = properties.GetString(JwtClaimTypes.AuthenticationTime);
		if (string.IsNullOrEmpty(authenticationTime))
		{
			throw new InvalidOperationException($"There is no {JwtClaimTypes.AuthenticationTime} in the properties");
		}

		if (!principal.IsAuthenticated())
			return null;

		// TODO think about the support for a list of several user accounts below
		var authSession = new AuthSession
		{
			AuthenticationType = principal.Identity!.AuthenticationType,
			Subject = principal.FindFirstValue(JwtClaimTypes.Subject).NotNull(JwtClaimTypes.Subject),

			SessionId = sessionId,
			AuthenticationTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(authenticationTime)),
			AuthContextClassRef = properties.GetString(JwtClaimTypes.AuthContextClassRef),
		};
		var affectedClientIdsJson = properties.GetString(nameof(AuthSession.AffectedClientIds));
		if (affectedClientIdsJson != null)
		{
			var affectedClientIdsArray = JsonSerializer.Deserialize<string[]>(affectedClientIdsJson);
			if (affectedClientIdsArray != null)
				authSession.AffectedClientIds = affectedClientIdsArray;
		}

		return authSession;
	}

	/// <summary>
	/// Signs in the specified user into the application.
	/// </summary>
	/// <param name="authSession">The authentication session details to be used for signing in.</param>
	/// <returns>A task that represents the asynchronous sign-in operation.</returns>
	public Task SignInAsync(AuthSession authSession)
	{
		var claims = new[] { new Claim(JwtClaimTypes.Subject, authSession.Subject) };
		var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authSession.AuthenticationType));

		var properties = new AuthenticationProperties();
		properties.SetString(JwtClaimTypes.SessionId, authSession.SessionId);
		properties.SetString(JwtClaimTypes.AuthenticationTime, authSession.AuthenticationTime.ToUnixTimeSeconds().ToString());
		properties.SetString(JwtClaimTypes.AuthContextClassRef, authSession.AuthContextClassRef);
		properties.SetString(nameof(AuthSession.AffectedClientIds), JsonSerializer.Serialize(authSession.AffectedClientIds));

		return HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, properties);
	}

	/// <summary>
	/// Updates the specified authentication session with the given client ID.
	/// </summary>
	/// <param name="authSession">The authentication session to be updated.</param>
	/// <param name="clientId">The client ID to be added to the session.</param>
	/// <returns>A task that represents the asynchronous update operation.</returns>
	public Task UpdateAsync(AuthSession authSession, string clientId)
	{
		if (authSession.AffectedClientIds.Contains(clientId))
			return Task.CompletedTask;

		authSession.AffectedClientIds = authSession.AffectedClientIds.Append(clientId);
		return SignInAsync(authSession);
	}

	/// <summary>
	/// Signs out the current user from the application.
	/// </summary>
	/// <returns>A task that represents the asynchronous sign-out operation.</returns>
	public Task SignOutAsync() => HttpContext.SignOutAsync();
}
