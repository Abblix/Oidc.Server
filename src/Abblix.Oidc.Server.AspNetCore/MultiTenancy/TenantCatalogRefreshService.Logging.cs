// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

internal sealed partial class TenantCatalogRefreshService
{
    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.CatalogRefreshFailed,
        Level = LogLevel.Error,
        Message = "Reading the store of tenants failed; the server keeps serving the tenants it last read and will " +
                  "read again in {RetryIn}. Until a reading succeeds, a tenant created, changed or removed since is " +
                  "not seen by this instance.")]
    private partial void LogRefreshFailed(Exception exception, TimeSpan retryIn);
}
