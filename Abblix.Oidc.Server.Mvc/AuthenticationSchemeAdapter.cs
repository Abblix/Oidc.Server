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

using System.Diagnostics.CodeAnalysis;
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

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Adapts ASP.NET Authentication Scheme to the <see cref="IAuthSessionService"/> interface.
/// This adapter allows the integration of the Abblix OIDC Server with standard ASP.NET authentication mechanisms,
/// enabling the use of existing authentication schemes to manage OIDC sessions.
/// </summary>
public class AuthenticationSchemeAdapter : IAuthSessionService
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AuthenticationSchemeAdapter"/> class,
	/// injecting dependencies needed to access and manage HTTP contexts.
	/// </summary>
	/// <param name="httpContextAccessor">Provides access to the <see cref="HttpContext"/>,
	/// allowing operations on the HTTP context of the current request.</param>
	public AuthenticationSchemeAdapter(IHttpContextAccessor httpContextAccessor)
	{
		_httpContextAccessor = httpContextAccessor;
	}

	private readonly IHttpContextAccessor _httpContextAccessor;

	/// <summary>
	/// Provides direct access to the current <see cref="HttpContext"/> by ensuring it is available and not null.
	/// </summary>
	private HttpContext HttpContext => _httpContextAccessor.HttpContext.NotNull(nameof(IHttpContextAccessor.HttpContext));

	/// <summary>
	/// Asynchronously retrieves the current user's authentication session if available.
	/// This method wraps ASP.NET's built-in authentication mechanisms to provide an <see cref="AuthSession"/> model.
	/// </summary>
	/// <returns>
	/// An asynchronous stream of <see cref="AuthSession"/> instances representing the user's current
	/// authentication sessions.
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
	/// Attempts to authenticate the current user based on the configured default authentication scheme,
	/// converting the authentication results into an <see cref="AuthSession"/>.
	/// </summary>
	/// <returns>
	/// A task that represents the asynchronous operation. The task result contains the <see cref="AuthSession"/>
	/// of the authenticated user or null if the authentication fails.
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
				$"Use {nameof(SessionIdGenerator)}.{nameof(SessionIdGenerator.GenerateSessionId)}() to generate a new session Id when calling .SignInAsync() method");
		}

		var authenticationTime = properties.GetString(JwtClaimTypes.AuthenticationTime);
		if (string.IsNullOrEmpty(authenticationTime))
		{
			throw new InvalidOperationException($"There is no {JwtClaimTypes.AuthenticationTime} in the properties");
		}

		if (!principal.IsAuthenticated())
			return null;

		// TODO think about the support for a list of several user accounts below
		var authSession = new AuthSession(
			principal.FindFirstValue(JwtClaimTypes.Subject).NotNull(JwtClaimTypes.Subject),
			sessionId,
			DateTimeOffset.FromUnixTimeSeconds(long.Parse(authenticationTime)),
			principal.Identity!.AuthenticationType.NotNull(nameof(ClaimsIdentity.AuthenticationType)))
		{
			AuthContextClassRef = properties.GetString(JwtClaimTypes.AuthContextClassRef),
		};

		if (TryGetStringArray(properties, nameof(AuthSession.AffectedClientIds), out var affectedClientIds))
			authSession = authSession with { AffectedClientIds = affectedClientIds };

		if (TryGetStringArray(properties, JwtClaimTypes.AuthenticationMethodReferences, out var authenticationMethodReferences))
			authSession = authSession with { AuthenticationMethodReferences = authenticationMethodReferences };

		return authSession;
	}

	/// <summary>
	/// Attempts to retrieve a list of strings from the <see cref="AuthenticationProperties"/>
	/// using the specified key. The value is expected to be stored as a JSON-serialized array of strings.
	/// </summary>
	/// <param name="properties">
	/// The <see cref="AuthenticationProperties"/> instance containing the serialized data.
	/// </param>
	/// <param name="key">
	/// The key used to locate the JSON-serialized array within the <paramref name="properties"/>.
	/// </param>
	/// <param name="values">
	/// When this method returns <c>true</c>, contains the deserialized list of strings associated with the specified key.
	/// Otherwise, the value is <c>null</c>.
	/// </param>
	/// <returns>
	/// <c>true</c> if a non-null, valid JSON array of strings was successfully retrieved and deserialized; otherwise, <c>false</c>.
	/// </returns>
	private static bool TryGetStringArray(
		AuthenticationProperties properties,
		string key,
		[NotNullWhen(true)] out List<string>? values)
	{
		var json = properties.GetString(key);
		if (json != null)
		{
			values = JsonSerializer.Deserialize<List<string>>(json);
			if (values != null)
				return true;
		}

		values = null;
		return false;
	}

	/// <summary>
	/// Signs in the specified user into the application, setting up their authentication session.
	/// </summary>
	/// <param name="authSession">The authentication session details to be used for signing in.</param>
	/// <returns>A task that represents the asynchronous sign-in operation.</returns>
	public Task SignInAsync(AuthSession authSession)
	{
		var claims = new[] { new Claim(JwtClaimTypes.Subject, authSession.Subject) };
		var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authSession.IdentityProvider));

		var properties = new AuthenticationProperties();
		properties.SetString(JwtClaimTypes.SessionId, authSession.SessionId);
		properties.SetString(JwtClaimTypes.AuthenticationTime, authSession.AuthenticationTime.ToUnixTimeSeconds().ToString());
		properties.SetString(JwtClaimTypes.AuthContextClassRef, authSession.AuthContextClassRef);
		properties.SetString(JwtClaimTypes.AuthenticationMethodReferences, JsonSerializer.Serialize(authSession.AuthenticationMethodReferences));
		properties.SetString(nameof(AuthSession.AffectedClientIds), JsonSerializer.Serialize(authSession.AffectedClientIds));

		return HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, properties);
	}

	/// <summary>
	/// Signs out the current user from the application, ending their authenticated session.
	/// </summary>
	/// <returns>A task that represents the asynchronous sign-out operation.</returns>
	public Task SignOutAsync() => HttpContext.SignOutAsync();
}
