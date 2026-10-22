// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

partial class ReleaseCheckingStreamStore
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.ReleasedStreamNotDeleted,
        Level = LogLevel.Error,
        Message = "The stream {StreamId} of receiver {ReceiverId} was written after its tenant {TenantId} was released "
                  + "and could not be deleted; it stays in the store until it is deleted by hand")]
    private partial void LogReleasedStreamNotDeleted(
        Exception exception,
        string ReceiverId,
        string StreamId,
        string TenantId);
}
