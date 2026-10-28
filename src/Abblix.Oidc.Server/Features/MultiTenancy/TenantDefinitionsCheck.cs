// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses a tenant with no address it can be reached at, and tenants sharing an id or an address.
/// </summary>
public sealed class TenantDefinitionsCheck : ITenantsCheck
{
    /// <summary>
    /// Refuses a tenant whose issuer's path lies under another tenant's on the same host.
    /// </summary>
    /// <remarks>
    /// A browser sends a cookie to every path under the one it was set for, so the sign-in cookie of the outer tenant
    /// would reach the inner one, and the end user arrive there signed in. Only the issuers' own addresses are
    /// compared: the end user signs in there, while a mutual-TLS host serves clients presenting a certificate.
    /// </remarks>
    private static IEnumerable<TenantRefusal> NestedIssuers(IReadOnlyCollection<TenantDefinition> tenants)
    {
        var addresses = (
            from tenant in tenants
            where IsIssuer(tenant.Issuer)
            select (tenant.Id, Address: TenantAddress.Of(tenant.Issuer).Canonical())
        ).ToArray();

        return (
            from outer in addresses
            from inner in addresses
            where !string.Equals(outer.Id, inner.Id, StringComparison.Ordinal) &&
                  string.Equals(outer.Address.Host, inner.Address.Host, StringComparison.Ordinal) &&
                  !string.Equals(outer.Address.Path, inner.Address.Path, StringComparison.Ordinal) &&
                  outer.Address.Covers(inner.Address.Path)
            select (Outer: outer.Id, Inner: inner.Id)
        ).Distinct().Select(nested => new TenantRefusal(
            [nested.Outer, nested.Inner],
            $"The issuer of tenant '{nested.Inner}' lies under that of tenant '{nested.Outer}' on the same host, " +
            $"so the sign-in cookie of '{nested.Outer}' would reach '{nested.Inner}'.")
        {
            PartyMessage = "its issuer and the issuer of another tenant lie one under the other on the same host, " +
                           "so the sign-in cookie of the outer tenant would reach the inner one.",
        });
    }

    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        var failures = new List<TenantRefusal>();

        // Required by the compiler only: configuration without the key, or a store holding none, gives no issuer
        failures.AddRange(
            from tenant in tenants
            where tenant.Issuer is null
            select TenantRefusal.Of(tenant, $"Tenant '{tenant.Id}' has no issuer."));

        failures.AddRange(
            from tenant in tenants
            where tenant.Issuer is not null
            let refusal = IssuerIdentifier.Refusal(tenant.Issuer, options.AllowHttpIssuer)
            where refusal is not null
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': {nameof(TenantDefinition.Issuer)} '{tenant.Issuer.OriginalString}' {refusal}."));

        // A Host header is ASCII, so a host with no ASCII form could never be requested.
        failures.AddRange(
            from tenant in tenants
            where IsIssuer(tenant.Issuer) && !TenantAddress.Of(tenant.Issuer).Host.All(char.IsAscii)
            select TenantRefusal.Of(
                tenant,
                $"The issuer '{tenant.Issuer.OriginalString}' of tenant '{tenant.Id}' names a host with no ASCII form, " +
                "which no request can carry."));

        failures.AddRange(
            from tenant in tenants
            group tenant by tenant.Id into same
            where same.Count() > 1
            select new TenantRefusal([same.Key], $"The tenant id '{same.Key}' is declared more than once."));

        // The mutual-TLS aliases carry the issuer path onto another host, so only the host is declared
        failures.AddRange(
            from tenant in tenants
            where tenant.MtlsBaseUri is not null && !IsMtlsHost(tenant.MtlsBaseUri)
            select TenantRefusal.Of(
                tenant,
                $"The mutual-TLS address '{tenant.MtlsBaseUri}' of tenant '{tenant.Id}' must be an absolute " +
                "https URL with no path, query or fragment: its aliases keep the tenant's issuer path."));

        // Compared as a request is resolved - host in one spelling, path without a trailing slash, scheme and
        // port left out - since two addresses equal on those would claim the same requests; a tenant's mutual-TLS
        // host under its issuer path is one of its addresses too.
        failures.AddRange(
            from tenant in tenants
            where IsIssuer(tenant.Issuer) && (tenant.MtlsBaseUri is null || IsMtlsHost(tenant.MtlsBaseUri))
            from address in TenantAddress.AllOf(tenant).Select(address => address.Canonical()).Distinct()
            group tenant.Id by address into same
            where same.Count() > 1
            select new TenantRefusal(
                [..same],
                $"The tenants {string.Join(", ", same)} are served at the same address " +
                $"{same.Key.Host}{same.Key.Path}.")
            {
                PartyMessage = $"it is served at the address {same.Key.Host}{same.Key.Path}, as another tenant is.",
            });

        failures.AddRange(NestedIssuers(tenants));

        // Refused here rather than when the first pairwise identifier is minted, which would answer with a 500
        failures.AddRange(
            from tenant in tenants
            let refusal = tenant.PairwiseSubject is { Salt: var salt, HashAlgorithm: var hashAlgorithm }
                ? PairwiseSubjectSettings.SaltRefusal(salt) ?? PairwiseSubjectSettings.HashAlgorithmRefusal(hashAlgorithm)
                : null
            where refusal is not null
            select TenantRefusal.Of(tenant, $"Tenant '{tenant.Id}': {refusal}"));

        return failures;
    }

    /// <remarks>
    /// Only the host is named: the aliases keep the issuer's path there, so a path of its own would move them to
    /// an address no request resolves to the tenant. A client presents its certificate over TLS, so https alone.
    /// </remarks>
    private static bool IsMtlsHost(Uri value)
        => value.IsAbsoluteUri &&
           value.Scheme == Uri.UriSchemeHttps &&
           value.AbsolutePath == "/" &&
           HasNoQueryOrFragment(value);

    /// <remarks>
    /// The checks of addresses read the issuer's, so they skip a tenant whose issuer has none to read; that tenant
    /// is refused for its issuer elsewhere. An http issuer has an address whether or not it is let through.
    /// </remarks>
    private static bool IsIssuer(Uri? issuer)
        => issuer is not null && IssuerIdentifier.Refusal(issuer, allowHttp: true) is null;

    /// <remarks>
    /// Asked only of an absolute address, since a relative one throws on either read.
    /// </remarks>
    private static bool HasNoQueryOrFragment(Uri value)
        => string.IsNullOrEmpty(value.Query) && string.IsNullOrEmpty(value.Fragment);
}
