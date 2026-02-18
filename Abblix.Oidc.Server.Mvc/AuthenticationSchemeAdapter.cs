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

using System.Globalization;
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
/// <param name="httpContextAccessor">Provides access to the <see cref="HttpContext"/>,
/// allowing operations on the HTTP context of the current request.</param>
/// <param name="authenticationScheme">The authentication scheme to use for all authentication operations.
/// This scheme will be explicitly specified when calling SignInAsync, SignOutAsync, and AuthenticateAsync methods.</param>
public class AuthenticationSchemeAdapter(
	IHttpContextAccessor httpContextAccessor,
	string authenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme) : IAuthSessionService
{
	/// <summary>
	/// Provides direct access to the current <see cref="HttpContext"/> by ensuring it is available and not null.
	/// </summary>
	private HttpContext HttpContext => httpContextAccessor.HttpContext.NotNull(nameof(IHttpContextAccessor.HttpContext));

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
	/// A task that returns the <see cref="AuthSession"/>
	/// of the authenticated user or null if the authentication fails.
	/// </returns>
	public async Task<AuthSession?> AuthenticateAsync()
	{
		var authenticationResult = await HttpContext.AuthenticateAsync(authenticationScheme);
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

		// NOTE: Future enhancement - consider supporting multiple user accounts per session
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
			claims.Add(new (JwtClaimTypes.AuthContextClassRef, authSession.AuthContextClassRef));

		// AuthenticationMethodReferences in claims (needed for session validation)
		if (authSession is { AuthenticationMethodReferences.Count: > 0 })
			claims.Add(new (JwtClaimTypes.AuthenticationMethodReferences, JsonSerializer.Serialize(authSession.AuthenticationMethodReferences)));

		// Email claim from AuthSession (preserves external provider email or challenge email)
		if (!string.IsNullOrEmpty(authSession.Email))
			claims.Add(new (JwtClaimTypes.Email, authSession.Email));

		// EmailVerified claim from AuthSession
		if (authSession.EmailVerified.HasValue)
			claims.Add(new (JwtClaimTypes.EmailVerified, authSession.EmailVerified.Value.ToString().ToLowerInvariant()));

		// Additional claims from JsonObject - serialize each property
		if (authSession.AdditionalClaims != null)
		{
			foreach (var (claimType, jsonNode) in authSession.AdditionalClaims)
			{
				if (jsonNode == null)
					continue;

				claims.Add(CreateClaim(claimType, jsonNode));
			}
		}

		var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authSession.IdentityProvider));

		var properties = new AuthenticationProperties();
		if (authSession is { AffectedClientIds.Count: > 0 })
			properties.SetString(nameof(AuthSession.AffectedClientIds), JsonSerializer.Serialize(authSession.AffectedClientIds));

		return HttpContext.SignInAsync(authenticationScheme, principal, properties);
	}

	/// <summary>
	/// Creates a Claim from a JsonNode value.
	/// Primitives are converted to their string representation with appropriate value type,
	/// complex types are JSON-serialized.
	/// </summary>
	private static Claim CreateClaim(string claimType, JsonNode claimValue)
	{
		// Handle arrays and objects - serialize as JSON
		if (claimValue is JsonArray or JsonObject)
			return new (claimType, claimValue.ToJsonString(), ClaimValueTypes.String);

		// Handle JsonValue<T> primitives
		if (claimValue is not JsonValue jsonValue)
			return new (claimType, claimValue.ToJsonString(), ClaimValueTypes.String);

		// Try to get the underlying value type
		if (jsonValue.TryGetValue<string>(out var stringValue))
			return new (claimType, stringValue, ClaimValueTypes.String);

		if (jsonValue.TryGetValue<bool>(out var boolValue))
			return new (claimType, boolValue.ToString().ToLowerInvariant(), ClaimValueTypes.Boolean);

		if (jsonValue.TryGetValue<int>(out var intValue))
			return new (claimType, intValue.ToString(), ClaimValueTypes.Integer32);

		if (jsonValue.TryGetValue<long>(out var longValue))
			return new (claimType, longValue.ToString(), ClaimValueTypes.Integer64);

		if (jsonValue.TryGetValue<float>(out var floatValue))
			return new (claimType, floatValue.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Double);

		if (jsonValue.TryGetValue<double>(out var doubleValue))
			return new (claimType, doubleValue.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Double);

		if (jsonValue.TryGetValue<decimal>(out var decimalValue))
			return new (claimType, decimalValue.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Double);

		// Using ISO 8601 round-trip format with full precision and timezone

		// For DateTime: "2009-06-15T13:45:30.0000000" or "2009-06-15T13:45:30.0000000Z"
		if (jsonValue.TryGetValue<DateTime>(out var dateTimeValue))
			return new (claimType, dateTimeValue.ToString("O"), ClaimValueTypes.DateTime);

		// For DateTimeOffset: "2009-06-15T13:45:30.0000000-07:00"
		if (jsonValue.TryGetValue<DateTimeOffset>(out var dateTimeOffsetValue))
			return new (claimType, dateTimeOffsetValue.ToString("O"), ClaimValueTypes.DateTime);

		// Fallback for any other JsonValue type
		return new (claimType, claimValue.ToJsonString(), ClaimValueTypes.String);
	}

	/// <summary>
	/// Signs out the current user from the application, ending their authenticated session.
	/// </summary>
	/// <returns>A task that represents the asynchronous sign-out operation.</returns>
	public Task SignOutAsync() => HttpContext.SignOutAsync(authenticationScheme);

	/// <summary>
	/// Extracts additional claims from the principal, excluding standard OIDC claims.
	/// Uses claim ValueType to preserve exact type information during round-trip serialization.
	/// </summary>
	private static JsonObject ExtractAdditionalClaims(ClaimsPrincipal principal)
	{
		var additionalClaims = new JsonObject();

		foreach (var claim in principal.Claims)
		{
			var isStandardClaim = claim.Type is
				JwtClaimTypes.Subject or
				JwtClaimTypes.SessionId or
				JwtClaimTypes.AuthenticationTime or
				JwtClaimTypes.AuthContextClassRef or
				JwtClaimTypes.Email or
				JwtClaimTypes.EmailVerified or
				JwtClaimTypes.AuthenticationMethodReferences;

			if (isStandardClaim)
				continue;

			additionalClaims[claim.Type] = TryParseJsonValue(claim);
		}

		return additionalClaims;
	}

	/// <summary>
	/// Parses a claim back to JsonNode using the claim's ValueType to preserve exact type information.
	/// Falls back to JSON parsing for complex types, then string value if all else fails.
	/// </summary>
	private static JsonNode? TryParseJsonValue(Claim claim)
	{
		var value = claim.Value;

		if (string.IsNullOrEmpty(value))
			return null;

		// Use ValueType to preserve exact type information from CreateClaim
		switch (claim.ValueType)
		{
			case ClaimValueTypes.Boolean when bool.TryParse(value, out var boolValue):
				return JsonValue.Create(boolValue);

			case ClaimValueTypes.Integer32 when int.TryParse(value, out var intValue):
				return JsonValue.Create(intValue);

			case ClaimValueTypes.Integer64 when long.TryParse(value, out var longValue):
				return JsonValue.Create(longValue);

			// Try decimal first (highest precision), then double
			case ClaimValueTypes.Double when decimal.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var decimalValue):
				return JsonValue.Create(decimalValue);

			case ClaimValueTypes.Double when double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var doubleValue):
				return JsonValue.Create(doubleValue);

			// Parse ISO 8601 format back to DateTimeOffset (preserves timezone)
			case ClaimValueTypes.DateTime when DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dateTimeOffsetValue):
				return JsonValue.Create(dateTimeOffsetValue);

			case ClaimValueTypes.DateTime when DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dateTimeValue):
				return JsonValue.Create(dateTimeValue);

			case ClaimValueTypes.String:
			case ClaimValueTypes.Boolean:
			case ClaimValueTypes.Integer32:
			case ClaimValueTypes.Integer64:
			case ClaimValueTypes.Double:
			case ClaimValueTypes.DateTime:
				return JsonValue.Create(value);

			default:
				// Try parsing as JSON for arrays/objects
				try
				{
					return JsonNode.Parse(value);
				}
				catch (JsonException)
				{
					// Fall back to string
					return JsonValue.Create(value);
				}
		}
	}
}
