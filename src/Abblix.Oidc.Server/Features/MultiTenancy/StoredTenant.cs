// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// A tenant as a store of tenants holds it.
/// </summary>
/// <param name="Tenant">The tenant's definition.</param>
/// <param name="Version">Changes whenever the definition does, and only then: while it stays, the server keeps
/// serving the definition it already holds and everything built from it.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed record StoredTenant(TenantDefinition Tenant, string Version);
