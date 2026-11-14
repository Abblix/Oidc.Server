// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

partial class TenantTransmitters
{
    [LoggerMessage(
        EventId = LogEvents.Transmitter.WriteSentAgain,
        Level = LogLevel.Information,
        Message = "A write to the streams of tenant {TenantId} was refused by the transmitter the tenant was served "
                  + "before it moved, and is sent again through the one it is served at {Issuer}")]
    private static partial void LogWriteSentAgain(ILogger logger, string TenantId, string Issuer);
}
