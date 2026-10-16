// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

partial class PollEndpointHandler
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.SetSigningFailed,
        Level = LogLevel.Error,
        Message = "SET {JwtId} on stream {StreamId} could not be signed, so the poll was not answered")]
    private partial void LogSigningFailed(Exception exception, string StreamId, string JwtId);

    [LoggerMessage(
        EventId = LogEvents.Transmitter.UnsendableItemDropped,
        Level = LogLevel.Error,
        Message = "Queued item {JwtId} on stream {StreamId} holds nothing that can be sent, so it was dropped")]
    private partial void LogUnsendableItemDropped(string StreamId, string JwtId);
}
