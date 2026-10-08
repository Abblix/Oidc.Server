// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

internal sealed partial class TenantCreations
{
    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.StoreTenantCatalog.TenantNotReleased,
        Level = LogLevel.Error,
        Message = "Something kept for the tenant {TenantId}, gone from the store, failed to be let go")]
    private partial void LogTenantNotReleased(Exception exception, string tenantId);

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.StoreTenantCatalog.TenantNotClosed,
        Level = LogLevel.Error,
        Message = "What the released tenant {TenantId} in generation '{Generation}' kept outside the server failed to be let go")]
    private partial void LogTenantNotClosed(Exception exception, string tenantId, string generation);
}
