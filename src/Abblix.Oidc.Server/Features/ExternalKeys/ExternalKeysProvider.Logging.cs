// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

partial class ExternalKeysProvider
{
    [LoggerMessage(
        EventId = LogEvents.Misc.ExternalKeysProvider.ServingLastKnownKeys,
        Level = LogLevel.Warning,
        Message = "The custodian could not be asked for the versions of '{KeyName}', so the {Count} version(s) " +
                  "last read are being published instead. They are what already-issued tokens verify against, " +
                  "but a rotation completed elsewhere during this outage is not among them.")]
    private partial void LogServingLastKnownKeys(string keyName, int count, Exception exception);
}
