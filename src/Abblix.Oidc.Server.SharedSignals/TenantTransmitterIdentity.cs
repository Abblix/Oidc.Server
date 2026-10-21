// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The transmitter as the tenant serving the request: its issuer, and addresses under that issuer.
/// </summary>
/// <remarks>
/// The options name the host without a path, and the paths they name are kept and put under the tenant's issuer,
/// the same way multi-tenancy serves every endpoint of a tenant under its issuer's path.
/// </remarks>
/// <param name="tenantAccessor">Names the tenant of the current request or scope.</param>
/// <param name="options">The transmitter's options, read for the path of the key set address.</param>
public sealed class TenantTransmitterIdentity(
    ITenantAccessor tenantAccessor,
    SharedSignalsTransmitterOptions options) : ITransmitterIdentity
{
    /// <inheritdoc />
    public string Issuer => Tenant.Issuer.OriginalString;

    /// <inheritdoc />
    public Uri? JwksUri => options.JwksUri is { } jwksUri ? Under(jwksUri.PathAndQuery) : null;

    /// <inheritdoc />
    public Uri EndpointsBase => Tenant.Issuer;

    /// <inheritdoc />
    public bool Serves => tenantAccessor.Current is not null;

    /// <inheritdoc />
    /// <remarks>
    /// The tenant's issuer: its receivers are clients of that tenant, and their credentials come from it.
    /// </remarks>
    public string? ReceiverIssuer => Tenant.Issuer.OriginalString;

    /// <inheritdoc />
    /// <remarks>
    /// Null outside a tenant rather than a refusal: a measurement taken there names no tenant instead of failing the
    /// work it measures.
    /// </remarks>
    public string? TenantId => tenantAccessor.Current?.Tenant.Id;

    private TenantDefinition Tenant => tenantAccessor.CurrentTenant();

    private Uri Under(string pathAndQuery) => new(Tenant.Issuer.OriginalString.TrimEnd('/') + pathAndQuery, UriKind.Absolute);
}
