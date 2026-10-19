// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Claims;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Reads, writes and removes the cookie of a session through its scheme's handler, carrying how the session is kept
/// as the properties the handler is given, and back.
/// </summary>
internal static class SessionCookie
{
    /// <summary>
    /// The session as a sign-in writes it: kept as the host stated, or when it stated nothing, as the end user's
    /// current session is, and as a browser session when there is none.
    /// </summary>
    /// <param name="signingIn">The session being signed in.</param>
    /// <param name="current">The end user's current session, or null when this is not a repeat sign-in of the same
    /// end user.</param>
    public static AuthSession Resolve(AuthSession signingIn, AuthSession? current)
        => signingIn.Persistence is SessionPersistence.UnstatedPersistence
            ? signingIn with { Persistence = current?.Persistence ?? SessionPersistence.BrowserSession }
            : signingIn;

    /// <summary>
    /// How the cookie a session was read from is kept, as its handler reports it.
    /// </summary>
    /// <remarks>
    /// A persistent cookie whose handler gave no expiry is read as unstated, so a repeat sign-in leaves the expiry to
    /// the handler again rather than guessing one.
    /// </remarks>
    /// <param name="authSession">The session read from the cookie.</param>
    /// <param name="result">What the cookie's handler reported when it read the cookie.</param>
    public static AuthSession Read(AuthSession authSession, AuthenticateResult result)
        => authSession with
        {
            Persistence = result.Properties switch
            {
                { IsPersistent: true, ExpiresUtc: { } expiresAt } => SessionPersistence.Until(expiresAt),
                { IsPersistent: true } => SessionPersistence.Unstated,
                _ => SessionPersistence.BrowserSession,
            },
        };

    /// <summary>
    /// A session read back from the cookie just written, kept as the session that was written is.
    /// </summary>
    /// <param name="read">The session as the cookie carries it.</param>
    /// <param name="written">The session it was written from.</param>
    public static AuthSession KeptAs(AuthSession read, AuthSession written)
        => read with { Persistence = written.Persistence };

    /// <summary>
    /// Reads the cookie of the scheme, with the properties its handler reports, how it is kept among them.
    /// </summary>
    /// <param name="httpContext">The request the cookie is read from.</param>
    /// <param name="authenticationScheme">The scheme whose handler reads the cookie.</param>
    public static Task<AuthenticateResult> AuthenticateAsync(HttpContext httpContext, string authenticationScheme)
        => httpContext.AuthenticateAsync(authenticationScheme);

    /// <summary>
    /// Writes the cookie of <paramref name="principal"/>, kept as <paramref name="authSession"/> states.
    /// </summary>
    /// <param name="httpContext">The request the cookie is written in.</param>
    /// <param name="authenticationScheme">The scheme whose handler writes the cookie.</param>
    /// <param name="principal">What the cookie carries.</param>
    /// <param name="authSession">The session the principal was built from.</param>
    public static Task SignInAsync(
        HttpContext httpContext,
        string authenticationScheme,
        ClaimsPrincipal principal,
        AuthSession authSession)
        => httpContext.SignInAsync(authenticationScheme, principal, Write(authSession));

    /// <summary>
    /// Removes the cookie of the scheme.
    /// </summary>
    /// <param name="httpContext">The request the cookie is removed in.</param>
    /// <param name="authenticationScheme">The scheme whose handler removes the cookie.</param>
    public static Task SignOutAsync(HttpContext httpContext, string authenticationScheme)
        => httpContext.SignOutAsync(authenticationScheme);

    /// <summary>
    /// The cookie properties <paramref name="authSession"/> is written with.
    /// </summary>
    private static AuthenticationProperties Write(AuthSession authSession) => authSession.Persistence switch
    {
        SessionPersistence.BrowserSessionPersistence => new AuthenticationProperties { IsPersistent = false },
        SessionPersistence.Persistent { ExpiresAt: var expiresAt } =>
            new AuthenticationProperties { IsPersistent = true, ExpiresUtc = expiresAt },

        // Only a session read back with a persistent cookie of no stated expiry: written the same way again
        SessionPersistence.UnstatedPersistence => new AuthenticationProperties { IsPersistent = true },

        var persistence => throw new UnexpectedTypeException(nameof(persistence), persistence.GetType()),
    };
}
