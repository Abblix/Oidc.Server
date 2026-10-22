// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The settings the current tenant declares in its <see cref="TenantDefinition"/>.
/// </summary>
/// <remarks>
/// Outside any tenant there are no settings to read, and each one refuses rather than answer with another
/// tenant's or with the server-wide value.
/// </remarks>
/// <param name="tenantAccessor">Resolves the current tenant.</param>
/// <param name="options">The server-wide settings a tenant's own are derived from.</param>
/// <param name="catalog">The catalog the tenants are resolved from, asked which definition is in force now.</param>
public sealed class TenantIssuerSettings(
    ITenantAccessor tenantAccessor,
    IOptionsMonitor<OidcOptions> options,
    ITenantCatalog catalog)
    : IIssuerSettings, ILicensedIssuer
{
    /// <inheritdoc />
    public string Id => Tenant.Id;

    /// <inheritdoc />
    public string KeyPartition => TenantKey.PartitionOf(Tenant);

    /// <inheritdoc />
    public CancellationToken Released => StoreTenantCatalog.ReleasedOf(catalog, Tenant);

    /// <inheritdoc />
    string? ILicensedIssuer.VouchedId(string issuer)
        => catalog is StoreTenantCatalog own &&
           own.InForce(Tenant) is { } served &&
           string.Equals(served.Issuer.OriginalString, issuer, StringComparison.Ordinal)
            ? served.Id
            : null;

    /// <inheritdoc />
    public ResourceDefinition[]? Resources => Tenant.Resources;

    /// <inheritdoc />
    public Uri? DefaultResourceIndicator => Tenant.DefaultResourceIndicator;

    /// <inheritdoc />
    public bool InferResourceFromScope => Tenant.InferResourceFromScope;

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

    /// <inheritdoc />
    /// <remarks>
    /// The configured name with the tenant's id after it, since tenants sharing a host share its cookies and each
    /// would otherwise overwrite the session the others' check-session pages read. A tenant's id holds only
    /// characters a cookie name may hold.
    /// </remarks>
    public string CheckSessionCookieName
        => $"{options.CurrentValue.CheckSessionCookie.Name}.{TenantKey.IdOf(Tenant)}";

    /// <inheritdoc />
    public Uri? MtlsBaseUri => Tenant.MtlsBaseUri;

    /// <inheritdoc />
    public MtlsAliasesOptions? MtlsEndpointAliases => Tenant.MtlsEndpointAliases;

    private TenantDefinition Tenant => tenantAccessor.CurrentTenant();
}
