// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
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
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantIssuerSettings(ITenantAccessor tenantAccessor, IOptionsMonitor<OidcOptions> options)
    : IIssuerSettings
{
    /// <inheritdoc />
    public string Id => Tenant.Id;

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

    /// <inheritdoc />
    public PairwiseSubjectSettings? PairwiseSubject => Tenant.PairwiseSubject;

    /// <inheritdoc />
    /// <remarks>
    /// The configured name with the tenant's id after it, since tenants sharing a host share its cookies and each
    /// would otherwise overwrite the session the others' check-session pages read. The id is escaped to the
    /// characters a cookie name may hold.
    /// </remarks>
    public string CheckSessionCookieName
        => $"{options.CurrentValue.CheckSessionCookie.Name}.{Uri.EscapeDataString(Tenant.Id)}";

    /// <inheritdoc />
    public IReadOnlyCollection<JsonWebKey> SigningKeys => Tenant.SigningKeys;

    /// <inheritdoc />
    public IReadOnlyCollection<JsonWebKey> EncryptionKeys => Tenant.EncryptionKeys;

    /// <inheritdoc />
    public CustodianHeldKeys? CustodianKeys => Tenant.CustodianKeys;

    /// <inheritdoc />
    public Uri? MtlsBaseUri => Tenant.MtlsBaseUri;

    private TenantDefinition Tenant => TenantKey.CurrentTenant(tenantAccessor);
}
