// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// How long the end user's session is kept by the user agent: until the browser closes, or past a restart until a
/// given moment. What a login page's "Keep me signed in" box chooses.
/// </summary>
/// <remarks>
/// A host states it on the session it signs in, and reads it back on the session it authenticates. Whether a
/// persistent session is renewed with activity is the host's own cookie setting; this states only where it starts.
/// </remarks>
public abstract record SessionPersistence
{
    private SessionPersistence()
    {
    }

    /// <summary>
    /// Nothing stated: a sign-in keeps what the end user's current session has, and a first sign-in starts a browser
    /// session. What a re-authentication or a step-up page that never shows the choice signs in with.
    /// </summary>
    public static SessionPersistence Unstated { get; } = new UnstatedPersistence();

    /// <summary>A session that ends when the browser closes.</summary>
    public static SessionPersistence BrowserSession { get; } = new BrowserSessionPersistence();

    /// <summary>A session that survives a browser restart until <paramref name="expiresAt"/>.</summary>
    /// <param name="expiresAt">The moment the user agent drops the session.</param>
    public static SessionPersistence Until(DateTimeOffset expiresAt) => new Persistent(expiresAt);

    /// <summary>Nothing stated, see <see cref="Unstated"/>.</summary>
    public sealed record UnstatedPersistence : SessionPersistence;

    /// <summary>A session that ends when the browser closes, see <see cref="BrowserSession"/>.</summary>
    public sealed record BrowserSessionPersistence : SessionPersistence;

    /// <summary>A session that survives a browser restart until <see cref="ExpiresAt"/>.</summary>
    /// <param name="ExpiresAt">The moment the user agent drops the session.</param>
    public sealed record Persistent(DateTimeOffset ExpiresAt) : SessionPersistence;
}
