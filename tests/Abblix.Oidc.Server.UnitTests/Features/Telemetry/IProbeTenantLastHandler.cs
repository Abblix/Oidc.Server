// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.UnitTests.Features.Telemetry;
using Abblix.Utils;

[assembly: ObservedEndpoint(typeof(IProbeTenantLastHandler), TelemetryEndpoints.Revocation)]

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// A handler handed its tenant after its request, listed in this suite so the build generates its decorator, which
/// has to find the tenant wherever it stands.
/// </summary>
public interface IProbeTenantLastHandler
{
    /// <summary>
    /// Handles a request at a tenant.
    /// </summary>
    Task<Result<string, OidcError>> HandleAsync(string request, TenantDefinition tenant);
}
