// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses to name an issuer for a request that was not resolved to a tenant, and otherwise asks the issuer
/// provider it decorates.
/// </summary>
/// <remarks>
/// In a multi-tenant deployment the issuer is the tenant's: resolution moves a tenant named in the path into
/// the request's path base, so the request-based issuer carries it, and a tenant reached by host name is that
/// host. A request that reached the server without a tenant has no issuer of its own, and answering with the
/// bare host would mint tokens every tenant on that host accepts.
/// </remarks>
public sealed class TenantGuardIssuerProvider(IIssuerProvider inner, ITenantAccessor tenantAccessor)
    : IIssuerProvider
{
    /// <inheritdoc />
    public string GetIssuer()
    {
        if (tenantAccessor.Current is null)
        {
            throw new InvalidOperationException(
                "The request was not resolved to a tenant, so it has no issuer. Reach the server through a host " +
                $"bound to a tenant or through a path naming one, with {nameof(MultiTenancyOptions)} listing it.");
        }

        return inner.GetIssuer();
    }
}
