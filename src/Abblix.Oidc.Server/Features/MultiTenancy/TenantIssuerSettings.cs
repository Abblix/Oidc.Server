// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;
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
    public IEnumerable<ClientInfo> Clients => Tenant.Clients;

    /// <inheritdoc />
    public ScopeDefinition[]? Scopes => Tenant.Scopes;

    /// <inheritdoc />
    public ResourceDefinition[]? Resources => Tenant.Resources;

    /// <inheritdoc />
    public Uri? DefaultResourceIndicator => Tenant.DefaultResourceIndicator;

    /// <inheritdoc />
    public Uri? AccountSelectionUri => Tenant.AccountSelectionUri;

    /// <inheritdoc />
    public Uri? ConsentUri => Tenant.ConsentUri;

    /// <inheritdoc />
    public Uri? InteractionUri => Tenant.InteractionUri;

    /// <inheritdoc />
    public Uri? LoginUri => Tenant.LoginUri;

    /// <inheritdoc />
    public Uri? RegistrationUri => Tenant.RegistrationUri;

    /// <inheritdoc />
    public ClientSecurityProfile DefaultSecurityProfile => Tenant.DefaultSecurityProfile;

    private TenantDefinition Tenant => TenantKey.CurrentTenant(tenantAccessor);
}
