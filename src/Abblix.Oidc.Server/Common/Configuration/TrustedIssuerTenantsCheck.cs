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
/// Refuses a tenant whose issuer is listed as a trusted issuer of the JWT bearer grant or of software statements.
/// </summary>
/// <remarks>
/// Both validate a token as one another issuer wrote, so nothing this server records about its own tokens is read
/// for it. Were a tenant of this server trusted there, a token the server issued and has since revoked or seen
/// replayed would still be accepted. The grant and the registration refuse such an issuer at each request too, also
/// when a host's own provider trusts it; this tells the operator at startup that the setting does nothing. The
/// server issues new tokens for its own through the refresh token and token exchange grants, which read those
/// records.
/// </remarks>
public sealed class TrustedIssuerTenantsCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => Failures(tenant, options));

    private static IEnumerable<string> Failures(TenantDefinition tenant, OidcOptions options)
    {
        if (Listed(tenant, options.JwtBearer.TrustedIssuers) is { } bearer)
        {
            yield return
                $"its issuer is listed as the trusted issuer '{bearer.Issuer}' of " +
                $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.TrustedIssuers)}, so tokens it issued " +
                "and revoked would be accepted as JWT bearer assertions, which the grant refuses instead.";
        }

        if (Listed(tenant, options.SoftwareStatement.TrustedIssuers) is { } statement)
        {
            yield return
                $"its issuer is listed as the trusted issuer '{statement.Issuer}' of " +
                $"{nameof(OidcOptions.SoftwareStatement)}.{nameof(SoftwareStatementOptions.TrustedIssuers)}, so " +
                "tokens it issued and revoked would be accepted as software statements, which registration " +
                "refuses instead.";
        }
    }

    private static TrustedIssuer? Listed(TenantDefinition tenant, IEnumerable<TrustedIssuer> trusted)
        => trusted.FirstOrDefault(issuer => issuer.Names(tenant.Issuer));
}
