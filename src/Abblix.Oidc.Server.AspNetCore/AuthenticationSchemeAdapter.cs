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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using static System.Globalization.CultureInfo;
using static System.Globalization.NumberStyles;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Adapts ASP.NET Authentication Scheme to the <see cref="IAuthSessionService"/> interface.
/// This adapter allows the integration of the Abblix OIDC Server with standard ASP.NET authentication mechanisms,
/// enabling the use of existing authentication schemes to manage OIDC sessions.
/// </summary>
/// <param name="httpContextAccessor">Provides access to the <see cref="HttpContext"/>,
/// allowing operations on the HTTP context of the current request.</param>
/// <param name="authSessionTerminator">Ends the session a sign-in replaces, for its tokens and its clients.</param>
/// <param name="clock">Tells when a session is signed in.</param>
/// <param name="authenticationScheme">The authentication scheme to use for all authentication operations.
/// This scheme will be explicitly specified when calling SignInAsync, SignOutAsync, and AuthenticateAsync methods.</param>
public class AuthenticationSchemeAdapter(
	IHttpContextAccessor httpContextAccessor,
	IAuthSessionTerminator authSessionTerminator,
	TimeProvider clock,
	string authenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme) : IAuthSessionService
{
	/// <summary>
	/// Claim names this adapter manages itself (the standard OIDC session claims). They are emitted from the typed
	/// <see cref="AuthSession"/> fields, so they must never be re-emitted from <see cref="AuthSession.AdditionalClaims"/>
	/// (a host- or browser-supplied additional claim keyed on one of these must not shadow the managed value), and they
	/// are excluded when reconstructing additional claims on read. A single set keeps the write-skip and the read-exclude
	/// from drifting apart.
	/// </summary>
	private static readonly HashSet<string> ReservedClaimTypes =
	[
		SignedInAtClaimType,
		JwtClaimTypes.Subject,
		IanaClaimTypes.Sid,
		IanaClaimTypes.AuthTime,
		IanaClaimTypes.Acr,
		IanaClaimTypes.Email,
		IanaClaimTypes.EmailVerified,
		IanaClaimTypes.Amr,
	];

	/// <summary>
	/// The claim the cookie keeps the moment a session was signed in under. It is the adapter's own, so it is reserved
	/// and never read back as an additional claim a token would carry.
	/// </summary>
	private const string SignedInAtClaimType = "abblix_signed_in_at";

	/// <summary>
	/// The request item holding the session this scheme last wrote, or null once it signed out, in the request.
	/// </summary>
	private (Type, string) WrittenInThisRequest => (typeof(AuthenticationSchemeAdapter), authenticationScheme);

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
	/// session are not modeled by this adapter.
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
	/// <para>
	/// Once this request has signed in or out, the answer is the session it wrote, or none, because the scheme keeps
	/// answering with the cookie the request arrived with for the rest of the request. That session is read from the
	/// claims as written, so a claims transformation the host registered reaches it only from the next request on.
	/// </para>
	/// </remarks>
	/// <returns>
	/// A task that returns the <see cref="AuthSession"/>
	/// of the authenticated user or null if the authentication fails.
	/// </returns>
	public async Task<AuthSession?> AuthenticateAsync()
	{
		if (HttpContext.Items.TryGetValue(WrittenInThisRequest, out var written))
			return (AuthSession?)written;

		var authenticationResult = await HttpContext.AuthenticateAsync(authenticationScheme);
		return authenticationResult.Succeeded ? ReadSession(authenticationResult.Principal) : null;
	}

	/// <summary>
	/// Reads the OIDC session a principal written by this adapter carries, or null when it carries none.
	/// </summary>
	/// <remarks>
	/// Built in two steps: the claims no session exists without, then the ones a session may carry.
	/// </remarks>
	private static AuthSession? ReadSession(ClaimsPrincipal principal)
		=> ReadRequiredClaims(principal) is { } authSession
			? WithOptionalClaims(authSession, principal)
			: null;

	/// <summary>
	/// The session the claims a session cannot exist without describe, or null when any of them is missing or
	/// malformed.
	/// </summary>
	private static AuthSession? ReadRequiredClaims(ClaimsPrincipal principal)
	{
		if (!principal.IsAuthenticated())
			return null;

		// All JWT claim types are stored as claims (not properties) for direct access. A cookie missing any of the
		// claims this adapter requires is not one of ours - return null instead of throwing.
		var subject = principal.FindFirstValue(JwtClaimTypes.Subject);
		if (string.IsNullOrEmpty(subject))
			return null;

		var sessionId = principal.FindFirstValue(IanaClaimTypes.Sid);
		if (string.IsNullOrEmpty(sessionId))
			return null;

		var authenticationTime = principal.FindFirstValue(IanaClaimTypes.AuthTime);
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
		return new AuthSession(
			subject,
			sessionId,
			authenticationTimeValue,
			identityProvider);
	}

	/// <summary>
	/// The moment the session was signed in, or null when the cookie carries none or one out of range, read as the
	/// authentication time is.
	/// </summary>
	private static DateTimeOffset? SignedInAtOf(ClaimsPrincipal principal)
	{
		if (!long.TryParse(principal.FindFirstValue(SignedInAtClaimType), Integer, InvariantCulture, out var seconds))
			return null;

		try
		{
			return DateTimeOffset.FromUnixTimeSeconds(seconds);
		}
		catch (ArgumentOutOfRangeException)
		{
			return null;
		}
	}

	/// <summary>
	/// Adds to a session the claims it may carry.
	/// </summary>
	private static AuthSession WithOptionalClaims(AuthSession authSession, ClaimsPrincipal principal)
	{
		authSession = authSession with
		{
			AuthContextClassRef = principal.FindFirstValue(IanaClaimTypes.Acr),
			Email = principal.FindFirstValue(IanaClaimTypes.Email),
			EmailVerified = bool.TryParse(principal.FindFirstValue(IanaClaimTypes.EmailVerified), out var emailVerified)
				? emailVerified
				: null,
			SignedInAt = SignedInAtOf(principal),
		};

		if (principal.TryGetStringList(IanaClaimTypes.Amr, out var authenticationMethodReferences))
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
	/// </summary>
	/// <remarks>
	/// The cookie holds one session, so signing in replaces the one it carries. When that session belongs to another
	/// end user, it is ended through <see cref="IAuthSessionTerminator"/> once the new cookie is written, and is
	/// reported as ended. When it belongs to the same end user, as on a re-authentication or a step-up, the session
	/// continues under its existing identifier: the clients signed in to it are recorded under that identifier and
	/// their ID tokens carry it, so a fresh one would lose them to the logout that follows.
	/// </remarks>
	/// <param name="authSession">The authentication session details to be used for signing in.</param>
	/// <returns>The session written, and the replaced session when it belonged to another end user.</returns>
	public async Task<AuthSessionSignInResult> SignInAsync(AuthSession authSession)
	{
		RequireReadableBack(authSession);

		var replaced = await AuthenticateAsync();
		AuthSession[] endedSessions = [];
		if (replaced != null && string.Equals(replaced.Subject, authSession.Subject, StringComparison.Ordinal))
			authSession = authSession with { SessionId = replaced.SessionId };
		else if (replaced != null)
			endedSessions = [replaced];

		var principal = BuildPrincipal(authSession with { SignedInAt = clock.GetUtcNow() });

		await HttpContext.SignInAsync(authenticationScheme, principal);

		// What the next request will read from this cookie, rather than the session passed in, so a read in this
		// request and the result get the same filtering and precision the cookie applies.
		var written = ReadSession(principal).NotNull(nameof(principal));
		HttpContext.Items[WrittenInThisRequest] = written;

		foreach (var endedSession in endedSessions)
			await authSessionTerminator.TerminateAsync(endedSession.SessionId, endedSession.Subject);

		return new AuthSessionSignInResult(written, endedSessions);
	}

	/// <summary>
	/// Refuses a session that would be written and then read back as no session.
	/// </summary>
	private static void RequireReadableBack(AuthSession authSession)
	{
		// IdentityProvider becomes the authentication type of the issued identity. An empty value produces an
		// unauthenticated principal: SignInAsync would appear to succeed, yet AuthenticateAsync would read it back as
		// "not authenticated" and return null, manifesting as a silent login loop. Fail fast at the source instead.
		if (string.IsNullOrEmpty(authSession.IdentityProvider))
			throw new ArgumentException(
				$"{nameof(AuthSession.IdentityProvider)} must be a non-empty value because it becomes the authentication " +
				"type of the issued identity; an empty value yields an unauthenticated principal that cannot be read back.",
				nameof(authSession));

		// The subject and the session id are what a read requires to see an OIDC session at all, so a session without
		// either would be written and then read as no session, by this request and every later one.
		if (string.IsNullOrEmpty(authSession.Subject))
			throw new ArgumentException(
				$"{nameof(AuthSession.Subject)} must be a non-empty value; a session without one is read back as no session.",
				nameof(authSession));

		if (string.IsNullOrEmpty(authSession.SessionId))
			throw new ArgumentException(
				$"{nameof(AuthSession.SessionId)} must be a non-empty value; a session without one is read back as no session.",
				nameof(authSession));
	}

	/// <summary>
	/// The principal the cookie stores for a session: its fields as claims, under its identity provider.
	/// </summary>
	private static ClaimsPrincipal BuildPrincipal(AuthSession authSession)
	{
		// Critical claims stored in principal for access in cookie events (especially SigningOut)
		var claims = new List<Claim>
		{
			new(JwtClaimTypes.Subject, authSession.Subject),
			new(IanaClaimTypes.Sid, authSession.SessionId),
			new(IanaClaimTypes.AuthTime, authSession.AuthenticationTime.ToUnixTimeSeconds().ToString(InvariantCulture)),
		};

		// Add optional claims if present
		if (!string.IsNullOrEmpty(authSession.AuthContextClassRef))
			claims.Add(new (IanaClaimTypes.Acr, authSession.AuthContextClassRef));

		// AuthenticationMethodReferences in claims (needed for session validation)
		if (authSession is { AuthenticationMethodReferences.Count: > 0 })
			claims.Add(new (IanaClaimTypes.Amr, JsonSerializer.Serialize(authSession.AuthenticationMethodReferences)));

		// Email claim from AuthSession (preserves external provider email or challenge email)
		if (!string.IsNullOrEmpty(authSession.Email))
			claims.Add(new (IanaClaimTypes.Email, authSession.Email));

		// EmailVerified claim from AuthSession
		if (authSession.EmailVerified.HasValue)
			claims.Add(new (IanaClaimTypes.EmailVerified, authSession.EmailVerified.Value.ToString().ToLowerInvariant()));

		if (authSession.SignedInAt.HasValue)
			claims.Add(new (SignedInAtClaimType, authSession.SignedInAt.Value.ToUnixTimeSeconds().ToString(InvariantCulture)));

		if (authSession.AdditionalClaims != null)
			AddAdditionalClaims(claims, authSession.AdditionalClaims);

		return new ClaimsPrincipal(new ClaimsIdentity(claims, authSession.IdentityProvider));
	}

	/// <summary>
	/// Serializes each additional claim. A claim keyed on a reserved name is skipped so it cannot shadow or duplicate
	/// a managed claim already emitted from the typed <see cref="AuthSession"/> fields.
	/// </summary>
	private static void AddAdditionalClaims(List<Claim> claims, JsonObject additionalClaims)
	{
		foreach (var (claimType, jsonNode) in additionalClaims)
		{
			if (jsonNode == null || ReservedClaimTypes.Contains(claimType))
				continue;

			claims.Add(JsonClaimValue.ToClaim(claimType, jsonNode));
		}
	}

	/// <summary>
	/// Signs out the current user from the application, ending their authenticated session.
	/// </summary>
	/// <returns>A task that represents the asynchronous sign-out operation.</returns>
	public async Task SignOutAsync()
	{
		await HttpContext.SignOutAsync(authenticationScheme);
		HttpContext.Items[WrittenInThisRequest] = null;
	}

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

			additionalClaims[claim.Type] = JsonClaimValue.FromClaim(claim);
		}

		return additionalClaims;
	}
}
