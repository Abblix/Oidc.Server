// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

internal partial class ReloadableClientInfoStorage
{
    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ReloadableClientInfoStorage.RegistrationEvicted,
        Level = LogLevel.Warning,
        Message = "A client registration under {ClientId} was dropped at the issuer '{IssuerId}' (empty for a " +
                  "server without tenants): its settings configure a client under that id")]
    private partial void LogRegistrationEvicted(string ClientId, string IssuerId);
}
