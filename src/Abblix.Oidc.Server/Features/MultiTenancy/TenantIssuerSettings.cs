// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The settings the current tenant declares in its <see cref="TenantDefinition"/>.
/// </summary>
/// <remarks>
/// Outside any tenant there are no settings to read, and each one refuses rather than answer with another
/// tenant's or with the server-wide value.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantIssuerSettings(ITenantAccessor tenantAccessor) : IIssuerSettings
{
    /// <inheritdoc />
    public IEnumerable<ClientInfo> Clients => TenantKey.CurrentTenant(tenantAccessor).Clients;
}
