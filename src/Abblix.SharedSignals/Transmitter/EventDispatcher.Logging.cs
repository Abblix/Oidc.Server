// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

partial class EventDispatcher
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.StreamNotReached,
        Level = LogLevel.Error,
        Message = "The event {EventType} could not be queued for stream {StreamId}; "
            + "the fan-out continued with the remaining streams")]
    private partial void LogStreamNotReached(Exception exception, string StreamId, string EventType);
}
