// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Telemetry;

partial class OidcInstruments
{
    [LoggerMessage(
        EventId = LogEvents.Telemetry.OidcInstruments.RequestRefused,
        Level = LogLevel.Debug,
        Message = "The {Endpoint} endpoint refused a request with {Error}")]
    private partial void LogRequestRefused(string Endpoint, string Error);
}
