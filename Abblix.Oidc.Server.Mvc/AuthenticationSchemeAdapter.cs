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

using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
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
	/// Initializes a new instance of the <see cref="AuthenticationSchemeAdapter"/> class with a specific authentication scheme,
	/// injecting dependencies needed to access and manage HTTP contexts.
	/// </summary>
	/// <param name="httpContextAccessor">Provides access to the <see cref="HttpContext"/>,
	/// allowing operations on the HTTP context of the current request.</param>
	/// <param name="authenticationScheme">The authentication scheme to use for all authentication operations.
	/// This scheme will be explicitly specified when calling SignInAsync, SignOutAsync, and AuthenticateAsync methods.</param>
	public AuthenticationSchemeAdapter(
		IHttpContextAccessor httpContextAccessor,
		string authenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme)
	{
		_httpContextAccessor = httpContextAccessor;
		_authenticationScheme = authenticationScheme;
	}

	private readonly IHttpContextAccessor _httpContextAccessor;
	
	/// <summary>
	/// The authentication scheme to use for all authentication operations (SignIn, SignOut, Authenticate).
	/// This ensures consistent behavior when multiple authentication schemes are registered.
	/// </summary>
	private readonly string _authenticationScheme;

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
		var authenticationResult = await HttpContext.AuthenticateAsync(_authenticationScheme);
		if (!authenticationResult.Succeeded)
			return null;

		var principal = authenticationResult.Principal;
		if (!principal.IsAuthenticated())
			return null;

		// All JWT claim types are now stored as claims (not properties) for direct access
		var sessionId = principal.FindFirstValue(JwtClaimTypes.SessionId);
		if (string.IsNullOrEmpty(sessionId))
		{
			throw new InvalidOperationException(
				$"Use {nameof(SessionIdGenerator)}.{nameof(SessionIdGenerator.GenerateSessionId)}() to generate a new session Id when calling .SignInAsync() method");
		}

		var authenticationTime = principal.FindFirstValue(JwtClaimTypes.AuthenticationTime);
		if (string.IsNullOrEmpty(authenticationTime))
		{
			throw new InvalidOperationException($"There is no {JwtClaimTypes.AuthenticationTime} in the claims");
		}

		// TODO think about the support for a list of several user accounts below
		var authSession = new AuthSession(
			principal.FindFirstValue(JwtClaimTypes.Subject).NotNull(JwtClaimTypes.Subject),
			sessionId,
			DateTimeOffset.FromUnixTimeSeconds(long.Parse(authenticationTime)),
			(principal.Identity?.AuthenticationType).NotNull(nameof(ClaimsIdentity.AuthenticationType)))
		{
			AuthContextClassRef = principal.FindFirstValue(JwtClaimTypes.AuthContextClassRef),
			Email = principal.FindFirstValue(JwtClaimTypes.Email),
			EmailVerified = bool.TryParse(principal.FindFirstValue(JwtClaimTypes.EmailVerified), out var emailVerified)
				? emailVerified
				: null,
		};

		var properties = authenticationResult.Properties;
		if (properties.TryGetStringList(nameof(AuthSession.AffectedClientIds), out var affectedClientIds))
			authSession = authSession with { AffectedClientIds = affectedClientIds };

		if (principal.TryGetStringList(JwtClaimTypes.AuthenticationMethodReferences, out var authenticationMethodReferences))
			authSession = authSession with { AuthenticationMethodReferences = authenticationMethodReferences };

		// Extract additional claims (exclude standard claims)
		var additionalClaims = ExtractAdditionalClaims(principal);
		if (additionalClaims.Count > 0)
			authSession = authSession with { AdditionalClaims = additionalClaims };

		return authSession;
	}

	/// <summary>
	/// Signs in the specified user into the application, setting up their authentication session.
	/// Critical claims (Subject, SessionId, AuthenticationTime, AuthenticationMethodReferences) are stored in principal claims.
	/// AffectedClientIds stored in properties as it's not needed in cookie events.
	/// </summary>
	/// <param name="authSession">The authentication session details to be used for signing in.</param>
	/// <returns>A task that represents the asynchronous sign-in operation.</returns>
	public Task SignInAsync(AuthSession authSession)
	{
		// Critical claims stored in principal for access in cookie events (especially SigningOut)
		var claims = new List<Claim>
		{
			new(JwtClaimTypes.Subject, authSession.Subject),
			new(JwtClaimTypes.SessionId, authSession.SessionId),
			new(JwtClaimTypes.AuthenticationTime, authSession.AuthenticationTime.ToUnixTimeSeconds().ToString()),
		};

		// Add optional claims if present
		if (!string.IsNullOrEmpty(authSession.AuthContextClassRef))
			claims.Add(new Claim(JwtClaimTypes.AuthContextClassRef, authSession.AuthContextClassRef));

		// AuthenticationMethodReferences in claims (needed for session validation)
		if (authSession is { AuthenticationMethodReferences.Count: > 0 })
			claims.Add(new Claim(JwtClaimTypes.AuthenticationMethodReferences, JsonSerializer.Serialize(authSession.AuthenticationMethodReferences)));

		// Email claim from AuthSession (preserves external provider email or challenge email)
		if (!string.IsNullOrEmpty(authSession.Email))
			claims.Add(new Claim(JwtClaimTypes.Email, authSession.Email));

		// EmailVerified claim from AuthSession
		if (authSession.EmailVerified.HasValue)
			claims.Add(new Claim(JwtClaimTypes.EmailVerified, authSession.EmailVerified.Value.ToString().ToLowerInvariant()));

		// Additional claims from JsonObject - serialize each property
		if (authSession.AdditionalClaims != null)
		{
			foreach (var (claimType, jsonValue) in authSession.AdditionalClaims)
			{
				if (jsonValue == null)
					continue;

				var claimValue = SerializeJsonValue(jsonValue);
				claims.Add(new Claim(claimType, claimValue));
			}
		}

		var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authSession.IdentityProvider));

		var properties = new AuthenticationProperties();
		if (authSession is { AffectedClientIds.Count: > 0 })
			properties.SetString(nameof(AuthSession.AffectedClientIds), JsonSerializer.Serialize(authSession.AffectedClientIds));

		return HttpContext.SignInAsync(_authenticationScheme, principal, properties);
	}

	/// <summary>
	/// Serializes a JsonNode to a string suitable for claim storage.
	/// Primitives are converted to their string representation, complex types are JSON-serialized.
	/// </summary>
	private static string SerializeJsonValue(JsonNode jsonValue)
	{
		return jsonValue switch
		{
			JsonValue jsonValueNode => jsonValueNode.GetValue<JsonElement>() switch
			{
				{ ValueKind: JsonValueKind.String } element => element.GetString()!,
				{ ValueKind: JsonValueKind.Number } element => element.ToString(),
				{ ValueKind: JsonValueKind.True } => "true",
				{ ValueKind: JsonValueKind.False } => "false",
				{ ValueKind: JsonValueKind.Null } => "",
				_ => jsonValue.ToJsonString()
			},
			JsonArray or JsonObject => jsonValue.ToJsonString(),
			_ => jsonValue.ToJsonString()
		};
	}

	/// <summary>
	/// Signs out the current user from the application, ending their authenticated session.
	/// </summary>
	/// <returns>A task that represents the asynchronous sign-out operation.</returns>
	public Task SignOutAsync() => HttpContext.SignOutAsync(_authenticationScheme);

	/// <summary>
	/// Extracts additional claims from the principal, excluding standard OIDC claims.
	/// Attempts to deserialize JSON values, falls back to string values.
	/// </summary>
	private static JsonObject ExtractAdditionalClaims(ClaimsPrincipal principal)
	{
		var additionalClaims = new JsonObject();

		foreach (var claim in principal.Claims)
		{
			if (IsStandardClaim(claim.Type))
				continue;

			var jsonValue = TryParseJsonValue(claim.Value);
			additionalClaims[claim.Type] = jsonValue;
		}

		return additionalClaims;
	}

	/// <summary>
	/// Attempts to parse a claim value as JSON, falling back to a simple string value.
	/// </summary>
	private static JsonNode? TryParseJsonValue(string value)
	{
		if (string.IsNullOrEmpty(value))
			return null;

		// Try parsing as JSON (for arrays/objects)
		try
		{
			return JsonNode.Parse(value);
		}
		catch (JsonException)
		{
			// Not JSON - try to detect type
			if (bool.TryParse(value, out var boolValue))
				return JsonValue.Create(boolValue);

			if (long.TryParse(value, out var longValue))
				return JsonValue.Create(longValue);

			if (double.TryParse(value, out var doubleValue))
				return JsonValue.Create(doubleValue);

			// Default to string
			return JsonValue.Create(value);
		}
	}

	private static bool IsStandardClaim(string claimType) => claimType switch
	{
		JwtClaimTypes.Subject => true,
		JwtClaimTypes.SessionId => true,
		JwtClaimTypes.AuthenticationTime => true,
		JwtClaimTypes.AuthContextClassRef => true,
		JwtClaimTypes.Email => true,
		JwtClaimTypes.EmailVerified => true,
		JwtClaimTypes.AuthenticationMethodReferences => true,
		_ => false
	};
}
