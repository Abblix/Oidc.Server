// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class SecurityProfileClientAuthenticator
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.SecurityProfileClientAuthenticator.RegistrationCannotSatisfyProfile,
        Level = LogLevel.Warning,
        Message = "The client {ClientId} authenticated, but its registration cannot satisfy the "
                  + "controls it is held to - it names {ClientProfile} and this deployment holds "
                  + "every client to {DeploymentProfile}: {@Violations}")]
    private partial void LogRegistrationCannotSatisfyProfile(
        string ClientId,
        string ClientProfile,
        ClientSecurityProfile DeploymentProfile,
        IReadOnlyList<string> Violations);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.SecurityProfileClientAuthenticator.ProfileIsNotOneThisServerDefines,
        Level = LogLevel.Warning,
        Message = "The client {ClientId} names security profile {Profile}, which this server does "
                  + "not define, so it is held to every control this server can demand")]
    private partial void LogProfileIsNotOneThisServerDefines(string ClientId, int Profile);
}
