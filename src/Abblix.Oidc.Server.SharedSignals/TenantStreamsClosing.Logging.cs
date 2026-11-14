// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

partial class TenantStreamsClosing
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.StreamNotDeleted,
        Level = LogLevel.Error,
        Message = "The stream {StreamId} of the released tenant {TenantId} could not be deleted; the tenant's other "
                  + "streams were")]
    private partial void LogStreamNotDeleted(Exception exception, string StreamId, string TenantId);
}
