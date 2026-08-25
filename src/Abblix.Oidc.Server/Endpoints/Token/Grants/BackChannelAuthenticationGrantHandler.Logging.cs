// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

partial class BackChannelAuthenticationGrantHandler
{
    /// <summary>
    /// The per-type validator's own words, which the client never sees.
    /// </summary>
    /// <remarks>
    /// A granted-phase rejection names a host-side defect, so the validator writes for whoever has to fix
    /// it and may name a tenant, a ceiling or a configuration key. The client is told only that the
    /// deployment will not issue these details; this is where the sentence that explains it lives.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Ciba.BackChannelAuthenticationGrantHandler.GrantedAuthorizationDetailsRefused,
        Level = LogLevel.Warning,
        Message = "Client {ClientId} redeemed a CIBA grant the per-type validators will not issue, so the " +
                  "request is refused and no token was issued: {Reason}")]
    private partial void LogGrantedAuthorizationDetailsRefused(string ClientId, string Reason);
}
