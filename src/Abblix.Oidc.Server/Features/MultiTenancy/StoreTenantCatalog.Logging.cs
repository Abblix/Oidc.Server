// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

public sealed partial class StoreTenantCatalog
{
    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.StoreTenantCatalog.TenantsLeftOut,
        Level = LogLevel.Error,
        Message = "The tenants {TenantIds} are left out of the tenants served, and requests to them are answered as " +
                  "to no tenant: {Refusal}")]
    private partial void LogTenantsLeftOut(string tenantIds, string refusal);

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.StoreTenantCatalog.TenantNotOpened,
        Level = LogLevel.Error,
        Message = "The tenant {TenantId} could not be readied to be served, so it is left out of the tenants " +
                  "served until a reading readies it, and requests to it are answered as to no tenant")]
    private partial void LogTenantNotOpened(Exception exception, string tenantId);
}
