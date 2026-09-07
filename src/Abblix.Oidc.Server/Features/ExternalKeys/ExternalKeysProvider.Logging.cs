// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
