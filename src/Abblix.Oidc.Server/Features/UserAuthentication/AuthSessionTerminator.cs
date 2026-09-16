// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// Ends a session through <see cref="ITokenRevoker"/> and <see cref="ISessionLogoutNotifier"/>.
/// </summary>
/// <param name="tokenRevoker">Revokes the tokens of the ended session, when the deployment asks for it.</param>
/// <param name="sessionLogoutNotifier">Notifies the clients of the ended session.</param>
/// <param name="options">Supplies whether ending a session revokes its tokens.</param>
public class AuthSessionTerminator(
    ITokenRevoker tokenRevoker,
    ISessionLogoutNotifier sessionLogoutNotifier,
    IOptions<OidcOptions> options) : IAuthSessionTerminator
{
    /// <inheritdoc />
    public async Task<LogoutContext> TerminateAsync(string sessionId, string subject)
    {
        // Recorded before any client is told, so a client acting on the notification cannot refresh its way
        // back in against a cutoff that has not been written yet.
        if (options.Value.RevokeSessionTokensOnLogout)
            await tokenRevoker.RevokeSessionAsync(sessionId);

        return await sessionLogoutNotifier.NotifyClientsAsync(sessionId, subject);
    }
}
