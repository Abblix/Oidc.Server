// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.UnitTests.Features.Telemetry;
using Abblix.Utils;

[assembly: ObservedEndpoint(typeof(IProbeHandler), TelemetryEndpoints.Introspection)]

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// A handler the library does not wrap, listed in this suite so the build generates its decorator as it does the
/// library's own.
/// </summary>
public interface IProbeHandler
{
    /// <summary>
    /// Handles a request.
    /// </summary>
    Task<Result<string, OidcError>> HandleAsync(string request);
}
