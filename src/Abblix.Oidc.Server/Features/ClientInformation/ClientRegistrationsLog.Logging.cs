// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

internal sealed partial class ClientRegistrationsLog
{
    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientRegistrationsLog.ClientRegistered,
        Level = LogLevel.Information,
        Message = "Tenant {TenantId} registered client {ClientId} as {Trust}, for grant types {GrantTypes}, scope " +
                  "{Scope} and resources {Resources}")]
    private partial void LogClientRegistered(
        string TenantId,
        Sanitized ClientId,
        ClientTrust Trust,
        Sanitized[] GrantTypes,
        Sanitized[]? Scope,
        Uri[]? Resources);

    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientRegistrationsLog.ClientUpdated,
        Level = LogLevel.Information,
        Message = "Tenant {TenantId} replaced the registration of client {ClientId}, now {Trust}, for grant types " +
                  "{GrantTypes}, scope {Scope} and resources {Resources}")]
    private partial void LogClientUpdated(
        string TenantId,
        Sanitized ClientId,
        ClientTrust Trust,
        Sanitized[] GrantTypes,
        Sanitized[]? Scope,
        Uri[]? Resources);

    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientRegistrationsLog.ClientRemoved,
        Level = LogLevel.Information,
        Message = "Tenant {TenantId} removed the registration of client {ClientId}")]
    private partial void LogClientRemoved(string TenantId, Sanitized ClientId);
}
