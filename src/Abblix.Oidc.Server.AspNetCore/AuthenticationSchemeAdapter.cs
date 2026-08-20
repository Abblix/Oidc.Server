// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Abblix.Utils.Collections;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using static System.Globalization.CultureInfo;
using static System.Globalization.DateTimeStyles;
using static System.Globalization.NumberStyles;

namespace Abblix.Oidc.Server.AspNetCore;

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
	/// Claim <see cref="Claim.ValueType"/> markers for the JSON node kinds the standard <see cref="ClaimValueTypes"/>
	/// set does not distinguish. The value type is the only channel that survives a claim being serialized into the
	/// authentication cookie, so the read side relies on these markers to reconstruct the exact node kind written.
	/// </summary>
	private static class CustomValueTypes
	{
		/// <summary>
		/// A JSON object, serialized to its JSON text. Matches <c>JsonClaimValueTypes.Json</c> of
		/// System.IdentityModel.Tokens.Jwt / Microsoft.IdentityModel, declared here by value
		/// so claims interoperate with JWT handlers without taking a dependency on those packages.
		/// </summary>
		public const string Json = "JSON";

		/// <summary>
		/// A JSON array, serialized to its JSON text. Matches <c>JsonClaimValueTypes.JsonArray</c> of
		/// System.IdentityModel.Tokens.Jwt / Microsoft.IdentityModel.
		/// </summary>
		public const string JsonArray = "JSON_ARRAY";

		/// <summary>
		/// A single-precision floating-point value - the <c>xs:float</c> XSD primitive type URI, a sibling of
		/// <c>ClaimValueTypes.Double</c> = <c>xs:double</c>.
		/// </summary>
		public const string Float = "http://www.w3.org/2001/XMLSchema#float";

		/// <summary>
		/// A decimal value - the <c>xs:decimal</c> XSD primitive type URI, a sibling of
		/// <c>ClaimValueTypes.Double</c> = <c>xs:double</c>.
		/// </summary>
		public const string Decimal = "http://www.w3.org/2001/XMLSchema#decimal";

		/// <summary>
		/// A <c>DateTimeOffset</c> - it has no XSD primitive distinct from <c>xs:dateTime</c> (which
		/// <c>ClaimValueTypes.DateTime</c> already uses for a <c>DateTime</c>), so it keeps a library-specific marker.
		/// </summary>
		public const string DateTimeOffset = "urn:abblix:datetimeoffset";
	}

	/// <summary>
	/// Claim names this adapter manages itself (the standard OIDC session claims). They are emitted from the typed
	/// <see cref="AuthSession"/> fields, so they must never be re-emitted from <see cref="AuthSession.AdditionalClaims"/>
	/// (a host- or browser-supplied additional claim keyed on one of these must not shadow the managed value), and they
	/// are excluded when reconstructing additional claims on read. A single set keeps the write-skip and the read-exclude
	/// from drifting apart.
	/// </summary>
	private static readonly HashSet<string> ReservedClaimTypes =
	[
		JwtClaimTypes.Subject,
		JwtClaimTypes.SessionId,
		JwtClaimTypes.AuthenticationTime,
		JwtClaimTypes.AuthContextClassRef,
		JwtClaimTypes.Email,
		JwtClaimTypes.EmailVerified,
		JwtClaimTypes.AuthenticationMethodReferences,
	];

	/// <summary>
	/// Provides direct access to the current <see cref="HttpContext"/> by ensuring it is available and not null.
	/// </summary>
	private HttpContext HttpContext => httpContextAccessor.HttpContext.NotNull(nameof(IHttpContextAccessor.HttpContext));

	/// <summary>
	/// Asynchronously retrieves the current user's authentication session if available.
	/// This method wraps ASP.NET's built-in authentication mechanisms to provide an <see cref="AuthSession"/> model.
	/// </summary>
	/// <remarks>
	/// The cookie-backed authentication scheme carries a single signed-in identity, so this stream yields at most one
	/// session - the one represented by the current request's cookie. Multiple concurrent user accounts per browser
	/// session are not modelled by this adapter.
	/// </remarks>
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
	/// <remarks>
	/// A cookie that authenticates under the configured scheme but does not carry the OIDC session claims this adapter
	/// writes (for example a plain application login cookie sharing the same scheme name, or a cookie whose claims are
	/// malformed) is treated as "no OIDC session" - the method returns null rather than throwing, so an unrelated cookie
	/// never turns a request into a 500.
	/// </remarks>
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

		// All JWT claim types are stored as claims (not properties) for direct access. A cookie missing any of the
		// claims this adapter requires is not one of ours - return null instead of throwing.
		var subject = principal.FindFirstValue(JwtClaimTypes.Subject);
		if (string.IsNullOrEmpty(subject))
			return null;

		var sessionId = principal.FindFirstValue(JwtClaimTypes.SessionId);
		if (string.IsNullOrEmpty(sessionId))
			return null;

		var authenticationTime = principal.FindFirstValue(JwtClaimTypes.AuthenticationTime);
		if (string.IsNullOrEmpty(authenticationTime) ||
		    !long.TryParse(authenticationTime, Integer, InvariantCulture, out var authenticationTimeSeconds))
			return null;

		DateTimeOffset authenticationTimeValue;
		try
		{
			authenticationTimeValue = DateTimeOffset.FromUnixTimeSeconds(authenticationTimeSeconds);
		}
		catch (ArgumentOutOfRangeException)
		{
			// A parseable but out-of-range Unix timestamp is a malformed cookie, not one of ours - no session.
			return null;
		}

		var identityProvider = principal.Identity?.AuthenticationType;
		if (string.IsNullOrEmpty(identityProvider))
			return null;

		// NOTE: Future enhancement - consider supporting multiple user accounts per session
		var authSession = new AuthSession(
			subject,
			sessionId,
			authenticationTimeValue,
			identityProvider)
		{
			AuthContextClassRef = principal.FindFirstValue(JwtClaimTypes.AuthContextClassRef),
			Email = principal.FindFirstValue(JwtClaimTypes.Email),
			EmailVerified = bool.TryParse(principal.FindFirstValue(JwtClaimTypes.EmailVerified), out var emailVerified)
				? emailVerified
				: null,
		};

		if (authenticationResult.Properties is { } properties &&
		    properties.TryGetStringList(nameof(AuthSession.AffectedClientIds), out var affectedClientIds))
			authSession = authSession with { AffectedClientIds = new ConcurrentSet<string>(affectedClientIds) };

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
		// IdentityProvider becomes the authentication type of the issued identity. An empty value produces an
		// unauthenticated principal: SignInAsync would appear to succeed, yet AuthenticateAsync would read it back as
		// "not authenticated" and return null, manifesting as a silent login loop. Fail fast at the source instead.
		if (string.IsNullOrEmpty(authSession.IdentityProvider))
			throw new ArgumentException(
				$"{nameof(AuthSession.IdentityProvider)} must be a non-empty value because it becomes the authentication " +
				"type of the issued identity; an empty value yields an unauthenticated principal that cannot be read back.",
				nameof(authSession));

		// Critical claims stored in principal for access in cookie events (especially SigningOut)
		var claims = new List<Claim>
		{
			new(JwtClaimTypes.Subject, authSession.Subject),
			new(JwtClaimTypes.SessionId, authSession.SessionId),
			new(JwtClaimTypes.AuthenticationTime, authSession.AuthenticationTime.ToUnixTimeSeconds().ToString(InvariantCulture)),
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

		// Additional claims from JsonObject - serialize each property. A claim keyed on a reserved name is skipped so it
		// cannot shadow or duplicate a managed claim already emitted from the typed AuthSession fields above.
		if (authSession.AdditionalClaims != null)
		{
			foreach (var (claimType, jsonNode) in authSession.AdditionalClaims)
			{
				if (jsonNode == null || ReservedClaimTypes.Contains(claimType))
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
	/// Primitives are converted to their string representation with a value type that pins the exact JSON kind,
	/// complex types (arrays and objects) are JSON-serialized and tagged so the read side parses them back.
	/// </summary>
	private static Claim CreateClaim(string claimType, JsonNode claimValue)
	{
		// Arrays and objects - serialize as JSON and tag so TryParseJsonValue parses them back into a JsonArray/JsonObject
		// rather than handing back the serialized string.
		if (claimValue is JsonObject)
			return new (claimType, claimValue.ToJsonString(), CustomValueTypes.Json);

		if (claimValue is JsonArray)
			return new (claimType, claimValue.ToJsonString(), CustomValueTypes.JsonArray);

		// Handle JsonValue<T> primitives
		if (claimValue is not JsonValue jsonValue)
			return new (claimType, claimValue.ToJsonString(), CustomValueTypes.Json);

		// Try to get the underlying value type. The order matters: string and bool first, then integers widest-last,
		// then the floating kinds, each tagged distinctly so the read side reconstructs the exact CLR/JSON type.
		if (jsonValue.TryGetValue<string>(out var stringValue))
			return new (claimType, stringValue, ClaimValueTypes.String);

		if (jsonValue.TryGetValue<bool>(out var boolValue))
			return new (claimType, boolValue.ToString().ToLowerInvariant(), ClaimValueTypes.Boolean);

		if (jsonValue.TryGetValue<int>(out var intValue))
			return new (claimType, intValue.ToString(InvariantCulture), ClaimValueTypes.Integer32);

		if (jsonValue.TryGetValue<long>(out var longValue))
			return new (claimType, longValue.ToString(InvariantCulture), ClaimValueTypes.Integer64);

		if (jsonValue.TryGetValue<float>(out var floatValue))
			return new (claimType, floatValue.ToString(InvariantCulture), CustomValueTypes.Float);

		if (jsonValue.TryGetValue<double>(out var doubleValue))
			return new (claimType, doubleValue.ToString(InvariantCulture), ClaimValueTypes.Double);

		if (jsonValue.TryGetValue<decimal>(out var decimalValue))
			return new (claimType, decimalValue.ToString(InvariantCulture), CustomValueTypes.Decimal);

		// ISO 8601 round-trip format ("O") with full precision. DateTime and DateTimeOffset are tagged distinctly so the
		// read side rebuilds the same CLR type: a DateTime keeps its Kind, a DateTimeOffset keeps its offset, neither is
		// silently coerced into the other (which would otherwise bake in the server's local offset).

		// For DateTime: "2009-06-15T13:45:30.0000000" or "2009-06-15T13:45:30.0000000Z"
		if (jsonValue.TryGetValue<DateTime>(out var dateTimeValue))
			return new (claimType, dateTimeValue.ToString("O", InvariantCulture), ClaimValueTypes.DateTime);

		// For DateTimeOffset: "2009-06-15T13:45:30.0000000-07:00"
		if (jsonValue.TryGetValue<DateTimeOffset>(out var dateTimeOffsetValue))
			return new (claimType, dateTimeOffsetValue.ToString("O", InvariantCulture), CustomValueTypes.DateTimeOffset);

		// Fallback for any other JsonValue type
		return new (claimType, claimValue.ToJsonString(), CustomValueTypes.Json);
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
			if (ReservedClaimTypes.Contains(claim.Type))
				continue;

			additionalClaims[claim.Type] = TryParseJsonValue(claim);
		}

		return additionalClaims;
	}

	/// <summary>
	/// Parses a claim back to JsonNode using the claim's ValueType to preserve exact type information.
	/// Falls back to JSON parsing for complex types, then the raw string value if all else fails.
	/// </summary>
	private static JsonNode? TryParseJsonValue(Claim claim)
	{
		var value = claim.Value;

		if (string.IsNullOrEmpty(value))
			return null;

		// Use ValueType to reconstruct the exact type CreateClaim recorded.
		return claim.ValueType switch
		{
			ClaimValueTypes.Boolean when bool.TryParse(value, out var boolValue) => JsonValue.Create(boolValue),

			ClaimValueTypes.Integer32 when int.TryParse(value, Integer, InvariantCulture, out var intValue)
				=> JsonValue.Create(intValue),

			ClaimValueTypes.Integer64 when long.TryParse(value, Integer, InvariantCulture, out var longValue)
				=> JsonValue.Create(longValue),

			CustomValueTypes.Float when float.TryParse(value, Float, InvariantCulture, out var floatValue)
				=> JsonValue.Create(floatValue),

			ClaimValueTypes.Double when double.TryParse(value, Float, InvariantCulture, out var doubleValue)
				=> JsonValue.Create(doubleValue),

			CustomValueTypes.Decimal when decimal.TryParse(value, Float, InvariantCulture, out var decimalValue)
				=> JsonValue.Create(decimalValue),

			ClaimValueTypes.DateTime when DateTime.TryParse(value, InvariantCulture, RoundtripKind, out var dateTimeValue)
				=> JsonValue.Create(dateTimeValue),

			CustomValueTypes.DateTimeOffset when DateTimeOffset.TryParse(value, InvariantCulture, RoundtripKind, out var dateTimeOffsetValue)
				=> JsonValue.Create(dateTimeOffsetValue),

			ClaimValueTypes.String or
				ClaimValueTypes.Boolean or
				ClaimValueTypes.Integer32 or
				ClaimValueTypes.Integer64 or
				ClaimValueTypes.Double or
				ClaimValueTypes.DateTime or
				CustomValueTypes.Float or
				CustomValueTypes.Decimal or
				CustomValueTypes.DateTimeOffset => JsonValue.Create(value),

			// The JSON markers, or a claim written by something other than CreateClaim - try to parse as JSON, and
			// fall back to the raw string when it is not valid JSON.
			_ => TryParseJsonNode(value),
		};
	}

	private static JsonNode? TryParseJsonNode(string value)
	{
		try
		{
			return JsonNode.Parse(value) ?? JsonValue.Create(value);
		}
		catch (JsonException)
		{
			return JsonValue.Create(value);
		}
	}
}
