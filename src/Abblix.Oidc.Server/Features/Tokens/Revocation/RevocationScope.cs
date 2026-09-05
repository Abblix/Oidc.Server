// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// The principal a revocation cutoff is recorded against.
/// </summary>
/// <remarks>
/// A cutoff is a single write that invalidates every token issued before a moment, so the scope decides how
/// wide that reaches. The two are stored apart because a subject identifier and a session identifier can
/// collide as strings, and a collision would revoke the wrong principal.
/// </remarks>
public enum RevocationScope
{
    /// <summary>
    /// Every token issued to one end user, across all of their sessions. What an account suspension, a
    /// password change or a "sign out everywhere" acts on.
    /// </summary>
    Subject,

    /// <summary>
    /// Every token issued within one session, leaving the same user's other sessions alone. What a logout
    /// from a single device acts on.
    /// </summary>
    Session,
}
