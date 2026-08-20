// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
