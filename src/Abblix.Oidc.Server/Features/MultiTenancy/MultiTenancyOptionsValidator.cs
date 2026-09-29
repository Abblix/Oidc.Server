// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a tenant list in which a tenant has no address, or two tenants share one.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class MultiTenancyOptionsValidator : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        var failures = new List<string>();

        failures.AddRange(
            from tenant in options.Tenants
            where string.IsNullOrEmpty(tenant.Id)
            select $"A tenant with the issuer '{tenant.Issuer}' has no id.");

        failures.AddRange(
            from tenant in options.Tenants
            where !IsIssuer(tenant.Issuer)
            select $"The issuer '{tenant.Issuer}' of tenant '{tenant.Id}' must be an http or https URL with no " +
                   "query or fragment.");

        // A Host header is ASCII, so a host with no ASCII form could never be requested.
        failures.AddRange(
            from tenant in options.Tenants
            where IsIssuer(tenant.Issuer) && !TenantAddress.Of(tenant.Issuer).Host.All(char.IsAscii)
            select $"The issuer '{tenant.Issuer}' of tenant '{tenant.Id}' names a host with no ASCII form, " +
                   "which no request can carry.");

        failures.AddRange(
            from tenant in options.Tenants
            group tenant by tenant.Id into same
            where same.Count() > 1
            select $"The tenant id '{same.Key}' is declared more than once.");

        // Compared as a request is resolved - host in one spelling, path without a trailing slash, scheme and
        // port left out - since two issuers equal on those would claim the same requests.
        failures.AddRange(
            from tenant in options.Tenants
            where IsIssuer(tenant.Issuer)
            group tenant.Id by TenantAddress.Of(tenant.Issuer).Canonical() into same
            where same.Count() > 1
            select $"The tenants {string.Join(", ", same)} are served at the same address " +
                   $"{same.Key.Host}{same.Key.Path}.");

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

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
