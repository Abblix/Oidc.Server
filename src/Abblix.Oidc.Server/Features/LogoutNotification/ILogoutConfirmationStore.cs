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
    /// end user and sent back with their answer.
    /// </summary>
    /// <param name="sessionId">The session the end user is being asked about.</param>
    /// <returns>The value, unguessable and good for one use.</returns>
    Task<string> IssueAsync(string sessionId);

    /// <summary>
    /// Redeems <paramref name="confirmation"/>, answering which session it was issued for, and spends it so the
    /// same answer cannot end a second session.
    /// </summary>
    /// <param name="confirmation">The value the request presented.</param>
    /// <returns>The session the value was issued for, or <c>null</c> when this caller is not the one that took
    /// it.</returns>
    /// <remarks>
    /// A caller is told it took the value only when the take-once protocol ran to the end and its own claim was
    /// still in the store. A refusal therefore covers the value not being there at all, another caller having
    /// taken it, and a claim that expired mid-protocol - the last on a single caller with nobody to lose to, its
    /// outcome being the value gone with nobody able to be told they took it. A store fault after the removal
    /// raises rather than answering, so it never reaches the refusal. Contract:
    /// <c>src/Abblix.Utils/DistributedCacheExtensions.cs</c>.
    /// <para>
    /// Every refusal means the same thing here, which is what makes this seam usable at all: the end user is
    /// asked again. A logout that asks twice costs a click; one that acts on an answer somebody else's browser
    /// gave, or on one already spent, costs the session.
    /// </para>
    /// </remarks>
    Task<string?> RedeemAsync(string confirmation);
}
