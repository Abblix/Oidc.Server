// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.MinimalApi;

internal static partial class PollEndpointAddresses
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.NoPollAddress,
        Level = LogLevel.Warning,
        Message = "No poll address can be composed for the stream identifier {StreamId}: a request to "
            + "{Address} reaches this transmitter naming something else, or nothing at all. Name the "
            + "stream something a URL path carries unchanged, or give it push delivery, which needs no "
            + "address of ours.")]
    private static partial void LogNoPollAddress(ILogger logger, Sanitized StreamId, Sanitized Address);
}
