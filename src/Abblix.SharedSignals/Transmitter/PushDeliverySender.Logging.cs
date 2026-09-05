// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

public sealed partial class PushDeliverySender
{
    /// <summary>
    /// The receiver refused SETs and they are out of the queue.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One line for the pass rather than one per SET. The queue is read whole, so a receiver refusing a
    /// backlog would otherwise write a line per event - thousands in a pass, differing only in an
    /// identifier, which is the drowning this exists to prevent.
    /// </para>
    /// <para>
    /// It says the events are out of the queue rather than that they can never be delivered, because those
    /// are different claims and only the first is certain. <c>invalid_key</c> is treated as final - a
    /// retransmission of the same bytes cannot succeed - yet the specification's own example of it is a
    /// revoked key (RFC 8935 Section 2.3), which the transmitter fixes on its own side. What the operator
    /// must know is that these events are gone, and why the receiver said so.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Transmitter.SetsRefusedByReceiver,
        Level = LogLevel.Warning,
        Message = "The receiver refused {RefusedCount} SET(s) on stream {StreamId} and they are out of the "
            + "queue: {ErrorCode} - {ErrorDescription}")]
    private partial void LogSetsRefused(
        string StreamId, int RefusedCount, string ErrorCode, string ErrorDescription);

    /// <summary>
    /// The receiver objected to this transmitter rather than to the SET, so the queue is held.
    /// </summary>
    /// <remarks>
    /// A separate event because the queue disposition differs, which is what an operator acts on: nothing is
    /// lost here, and the events go out once the credential or the grant is put right. The pass stops at the
    /// first such answer, so this is one line per stream per pass - paced by whatever drives the passes, and
    /// the package's own sweeper carries no backoff.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Transmitter.ReceiverObjected,
        Level = LogLevel.Warning,
        Message = "The receiver objected to this transmitter rather than to the SET on stream {StreamId}, so "
            + "the queue is held for a later pass: {ErrorCode} - {ErrorDescription}")]
    private partial void LogReceiverObjected(string StreamId, string ErrorCode, string ErrorDescription);
}
