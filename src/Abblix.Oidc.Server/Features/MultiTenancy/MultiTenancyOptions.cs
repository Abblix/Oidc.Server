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
/// The tenants a deployment serves.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class MultiTenancyOptions
{
    /// <summary>
    /// The tenants this deployment serves, each reached at its issuer.
    /// </summary>
    public List<TenantDefinition> Tenants { get; set; } = [];
}
