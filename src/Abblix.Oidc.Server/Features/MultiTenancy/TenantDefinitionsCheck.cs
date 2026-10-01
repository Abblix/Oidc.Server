// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses a tenant with no id or no address it can be reached at, and tenants sharing an id or an address.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantDefinitionsCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants)
    {
        var failures = new List<TenantRefusal>();

        failures.AddRange(
            from tenant in tenants
            where string.IsNullOrEmpty(tenant.Id)
            select TenantRefusal.Of(tenant, $"A tenant with the issuer '{tenant.Issuer}' has no id."));

        failures.AddRange(
            from tenant in tenants
            where !IsIssuer(tenant.Issuer)
            select TenantRefusal.Of(
                tenant,
                $"The issuer '{tenant.Issuer}' of tenant '{tenant.Id}' must be an http or https URL with no " +
                "query or fragment."));

        // A Host header is ASCII, so a host with no ASCII form could never be requested.
        failures.AddRange(
            from tenant in tenants
            where IsIssuer(tenant.Issuer) && !TenantAddress.Of(tenant.Issuer).Host.All(char.IsAscii)
            select TenantRefusal.Of(
                tenant,
                $"The issuer '{tenant.Issuer}' of tenant '{tenant.Id}' names a host with no ASCII form, " +
                "which no request can carry."));

        // It is part of the names the tenant's data and keys are kept under, which every store accepts in this form
        failures.AddRange(
            from tenant in tenants
            where !TenantKey.IsPartitionSegment(tenant.Generation)
            select TenantRefusal.Of(
                tenant,
                $"The generation '{tenant.Generation}' of tenant '{tenant.Id}' must hold only letters, digits, " +
                "'-' and '_'."));

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
                $"{same.Key.Host}{same.Key.Path}."));

        // Refused here rather than when the first pairwise identifier is minted, which would answer with a 500
        failures.AddRange(
            from tenant in tenants
            let refusal = tenant.PairwiseSubject is { Salt: var salt }
                ? PairwiseSubjectSettings.SaltRefusal(salt)
                : null
            where refusal is not null
            select TenantRefusal.Of(tenant, $"Tenant '{tenant.Id}': {refusal}"));

        failures.AddRange(
            from tenant in tenants
            let refusal = PairwiseClientsOptionsValidator.Refusal(tenant.Clients, tenant.PairwiseSubject)
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
           string.IsNullOrEmpty(value.Query) &&
           string.IsNullOrEmpty(value.Fragment);

    /// <remarks>
    /// OpenID Connect Discovery 1.0 section 3 and RFC 8414 section 2 make the issuer an https URL; http is let
    /// through for a server run locally. The scheme is checked by name because on Unix a bare path parses as an
    /// absolute file address, whose empty host a request without a Host header would match.
    /// </remarks>
    private static bool IsIssuer(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var issuer) &&
           (issuer.Scheme == Uri.UriSchemeHttps || issuer.Scheme == Uri.UriSchemeHttp) &&
           string.IsNullOrEmpty(issuer.Query) &&
           string.IsNullOrEmpty(issuer.Fragment);
}
