// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

public sealed partial class PushDeliverySender
{
    /// <summary>
    /// Stands in for a receiver that answered 400 without the error body RFC 8935 Section 2.3 asks of it.
    /// </summary>
    /// <remarks>
    /// Written into the log rather than left empty so that the two cases read differently: a receiver that
    /// explained itself and one that did not are different problems, and an absent field looks the same as a
    /// field nobody wrote.
    /// </remarks>
    private const string NoVerdict = "(the receiver sent no error body)";

    [LoggerMessage(
        EventId = LogEvents.Transmitter.SetRefusedByReceiver,
        Level = LogLevel.Warning,
        Message = "The receiver refused SET {JwtId} on stream {StreamId} for good and it will not be sent "
            + "again: {ErrorCode} - {ErrorDescription}")]
    private partial void LogSetRefused(string StreamId, string JwtId, string ErrorCode, string ErrorDescription);

    [LoggerMessage(
        EventId = LogEvents.Transmitter.ReceiverObjected,
        Level = LogLevel.Warning,
        Message = "The receiver objected to this transmitter rather than to the SET on stream {StreamId}, so "
            + "the queue is held for a later pass: {ErrorCode} - {ErrorDescription}")]
    private partial void LogReceiverObjected(string StreamId, string ErrorCode, string ErrorDescription);
}
