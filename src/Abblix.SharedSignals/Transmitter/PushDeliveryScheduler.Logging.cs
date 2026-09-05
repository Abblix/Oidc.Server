// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

partial class PushDeliveryScheduler
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.PushSweepFailed,
        Level = LogLevel.Error,
        Message = "A push delivery sweep failed; the next one runs in {RetryIn}")]
    private partial void LogSweepFailed(Exception exception, TimeSpan RetryIn);

    [LoggerMessage(
        EventId = LogEvents.Transmitter.PushStreamFailed,
        Level = LogLevel.Warning,
        Message = "Push delivery failed for stream {StreamId}; the sweep continued with the rest")]
    private partial void LogStreamFailed(Exception exception, string StreamId);

    [LoggerMessage(
        EventId = LogEvents.Transmitter.PushSweepingStarted,
        Level = LogLevel.Information,
        Message = "Sweeping push streams every {Interval}, claiming each through {LeaseImplementation}")]
    private partial void LogSweepingStarted(TimeSpan Interval, string LeaseImplementation);

    [LoggerMessage(
        EventId = LogEvents.Transmitter.PushStreamClaimedElsewhere,
        Level = LogLevel.Debug,
        Message = "Stream {StreamId} is being delivered by another instance; skipped this round")]
    private partial void LogStreamClaimedElsewhere(string StreamId);

    [LoggerMessage(
        EventId = LogEvents.Transmitter.PushPassCutOff,
        Level = LogLevel.Warning,
        Message = "Delivery of stream {StreamId} outlived its {LeaseDuration} claim and was cut off; "
                  + "what it did not deliver goes out on a later pass")]
    private partial void LogStreamPassCutOff(string StreamId, TimeSpan LeaseDuration);
}
