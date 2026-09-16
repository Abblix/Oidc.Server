// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Issues and redeems the value that carries an end user's answer to the logout question back to this server.
/// </summary>
/// <remarks>
/// OpenID Connect RP-Initiated Logout 1.0 section 2 makes the server ask the end user whether to log out, and its
/// section 6 says why: a logout request nobody asked for is a denial of service. The answer therefore has to be
/// something only this server could have handed to the page it rendered: a value the caller can state for itself
/// would let any site end a session by naming it.
/// </remarks>
public interface ILogoutConfirmationStore
{
    /// <summary>
    /// Issues the value that answers for <paramref name="sessionId"/>, to be rendered into the page that asks the
    /// end user and sent back with their answer. A session has one outstanding question at a time: asking again
    /// while it stands answers with the same value, so a request arriving while the end user reads the page
    /// cannot void the answer they are about to give.
    /// </summary>
    /// <param name="sessionId">The session the end user is being asked about.</param>
    /// <returns>The value, unguessable and good until it is answered or expires.</returns>
    Task<string> IssueAsync(string sessionId);

    /// <summary>
    /// Answers whether <paramref name="confirmation"/> is the value <paramref name="sessionId"/> was asked with,
    /// and spends the question when it is, so a value captured from a page stops being an answer once it has been
    /// given. Two identical answers arriving together can both be told they took it; each of them asked to end
    /// the same session, which is what happens.
    /// </summary>
    /// <param name="sessionId">The session the request would end.</param>
    /// <param name="confirmation">The value the request presented.</param>
    /// <returns><c>true</c> when the end user answered this session's question; <c>false</c> when that session has
    /// no question outstanding, when the question has expired or been answered already, and when the value is not
    /// the one it was asked with.</returns>
    /// <remarks>
    /// Every <c>false</c> means the same thing to the caller, which is what makes this seam usable at all: the end
    /// user is asked again, and a fresh question replaces whatever stood before. A logout that asks twice costs a
    /// click; one that acts on an answer somebody else's browser gave, or on one already spent, costs the session.
    /// </remarks>
    Task<bool> RedeemLogoutConfirmationAsync(string sessionId, string confirmation);
}
