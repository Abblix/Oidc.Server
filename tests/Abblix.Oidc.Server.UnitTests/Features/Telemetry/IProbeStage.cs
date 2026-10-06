// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.UnitTests.Features.Telemetry;
using Abblix.Utils;

[assembly: ObservedStage(typeof(IProbeStage), TelemetryStages.Validation)]

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// A stage the library does not wrap, listed in this suite so the build generates its decorator as it does the
/// library's own; its refusal is an error type the endpoint observation could not read, which a stage reads anyway.
/// </summary>
public interface IProbeStage
{
    /// <summary>
    /// Checks a request.
    /// </summary>
    Task<Result<string, int>> CheckAsync(string request);
}
