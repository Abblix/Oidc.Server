// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        ClientSecurityProfile ClientProfile,
        ClientSecurityProfile DeploymentProfile,
        IReadOnlyList<string> Violations);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.SecurityProfileClientAuthenticator.ProfileIsNotOneThisServerDefines,
        Level = LogLevel.Warning,
        Message = "The client {ClientId} names security profile {Profile}, which this server does "
                  + "not define, so it is held to every control this server can demand")]
    private partial void LogProfileIsNotOneThisServerDefines(string ClientId, int Profile);

    /// <remarks>
    /// A message of its own rather than a sentinel in <c>ClientProfile</c>: the client named
    /// nothing, so there is no value to carry, and a sentinel would put a string in that field
    /// which no type protects and which every consumer would have to know by heart.
    ///
    /// Its own event id follows from the same reasoning: an absent case selected by an id that is
    /// PRESENT beats one selected by a missing field, which a consumer cannot tell apart from a
    /// field dropped somewhere in the pipeline.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.SecurityProfileClientAuthenticator.RegistrationCannotSatisfyDeploymentProfile,
        Level = LogLevel.Warning,
        Message = "The client {ClientId} authenticated, but its registration cannot satisfy the "
                  + "controls it is held to - it names no profile of its own and this deployment "
                  + "holds every client to {DeploymentProfile}: {@Violations}")]
    private partial void LogRegistrationCannotSatisfyDeploymentProfile(
        string ClientId,
        ClientSecurityProfile DeploymentProfile,
        IReadOnlyList<string> Violations);
}
