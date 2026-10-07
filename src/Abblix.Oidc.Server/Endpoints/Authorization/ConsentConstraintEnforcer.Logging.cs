// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

public partial class ConsentConstraintEnforcer
{
    /// <summary>
    /// A per-type validator found a granted entry wider than the requested ones, and the client is told
    /// access_denied. Warning, because somebody outside the server did something wrong, most likely an
    /// end user who edited the consent form.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.AuthorizationConsent.ConsentConstraintEnforcer.GrantedAuthorizationDetailsExceedTheRequest,
        Level = LogLevel.Warning,
        Message = "The authorization_details granted to client {ClientId} exceed the ones requested: {Reason}")]
    private partial void LogGrantedAuthorizationDetailsExceedTheRequest(string ClientId, string? Reason);
}
