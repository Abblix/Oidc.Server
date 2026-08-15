// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
}
