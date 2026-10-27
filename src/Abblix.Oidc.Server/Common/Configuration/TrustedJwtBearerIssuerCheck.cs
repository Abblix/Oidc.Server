// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant whose issuer is listed as a trusted issuer of the JWT bearer grant.
/// </summary>
/// <remarks>
/// The grant validates an assertion as a token another issuer wrote, so nothing this server records about its own
/// tokens is read for it. Were a tenant of this server trusted there, a token the server issued and has since revoked
/// or seen replayed would still be accepted as an assertion. The server issues new tokens for its own through the
/// refresh token and token exchange grants, which read those records.
/// </remarks>
public sealed class TrustedJwtBearerIssuerCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => Failures(tenant, options.JwtBearer.TrustedIssuers));

    private static IEnumerable<string> Failures(TenantDefinition tenant, IEnumerable<TrustedIssuer> trusted)
    {
        if (trusted.FirstOrDefault(issuer => issuer.Names(tenant.Issuer)) is not { } listed)
            yield break;

        yield return
            $"its issuer is listed as the trusted issuer '{listed.Issuer}' of " +
            $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.TrustedIssuers)}, so tokens it issued and " +
            "revoked would still be accepted as JWT bearer assertions.";
    }
}
