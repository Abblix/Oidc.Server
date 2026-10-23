// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

public sealed partial class TenantManager
{
    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.TenantManager.ChangeNotServedYet,
        Level = LogLevel.Warning,
        Message = "A change of the tenants is stored, but reading the store again failed, so this instance serves " +
                  "it from its next reading")]
    private partial void LogChangeNotServedYet(Exception exception);

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.TenantManager.ConflictToldWithoutTheOthers,
        Level = LogLevel.Warning,
        Message = "A change of tenant {TenantId} is refused for a conflict with other tenants, which the refusal " +
                  "returned does not name: {Refusal}")]
    private partial void LogConflictToldWithoutTheOthers(string tenantId, string refusal);
}
