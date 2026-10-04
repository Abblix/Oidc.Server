// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

partial class TenantPushDeliverySweep
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.TenantSweepFailed,
        Level = LogLevel.Error,
        Message = "The push delivery pass of tenant {TenantId} failed; the other tenants' passes ran")]
    private partial void LogTenantSweepFailed(Exception exception, string TenantId);
}
