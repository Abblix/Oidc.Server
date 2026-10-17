// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Stands in for a host that registered no provider of user information: it knows no user.
/// </summary>
/// <remarks>
/// Whoever it is asked about is unknown, so no ID token is issued and the user information endpoint answers
/// invalid_token. Each such question is logged, since a host serving end users that forgot its provider learns of it
/// only this way.
/// </remarks>
/// <param name="logger">Tells that the server was asked about a user with no provider to answer.</param>
internal sealed partial class NoUserInfoProvider(ILogger<NoUserInfoProvider> logger) : IUserInfoProvider
{
    /// <inheritdoc />
    public Task<JsonObject?> GetUserInfoAsync(AuthSession authSession, IEnumerable<string> requestedClaims)
    {
        LogNoProviderRegistered();
        return Task.FromResult<JsonObject?>(null);
    }

    [LoggerMessage(
        EventId = LogEvents.Misc.NoUserInfoProvider.NoProviderRegistered,
        Level = LogLevel.Warning,
        Message = "The server was asked about an end user, and the host registered no IUserInfoProvider to answer, " +
                  "so the user is unknown")]
    private partial void LogNoProviderRegistered();
}
