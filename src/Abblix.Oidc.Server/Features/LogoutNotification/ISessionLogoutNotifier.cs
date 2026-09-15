// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Tells every client that signed in to a session that the session has ended.
/// </summary>
/// <remarks>
/// The clients are the ones <see cref="Storages.ISessionClientRegistry"/> recorded for the session, and each is
/// notified through <see cref="ILogoutNotifier"/>. A client whose notification fails is logged and the others are
/// still notified, so an unreachable client cannot fail the logout it is being told about.
/// </remarks>
public interface ISessionLogoutNotifier
{
    /// <summary>
    /// Notifies the clients of an ended session.
    /// </summary>
    /// <param name="sessionId">The session that ended.</param>
    /// <param name="subject">The end user the session belonged to.</param>
    /// <returns>
    /// The logout context the notifiers filled in, whose front-channel URIs the caller renders to the user agent.
    /// </returns>
    Task<LogoutContext> NotifyClientsAsync(string sessionId, string subject);
}
