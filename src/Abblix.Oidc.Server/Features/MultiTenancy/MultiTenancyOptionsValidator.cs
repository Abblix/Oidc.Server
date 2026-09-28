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
/// Refuses at startup a tenant list that would resolve a request to more than one tenant, to one no request can
/// reach, or to an issuer another tenant also claims.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class MultiTenancyOptionsValidator : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        var failures = new List<string>();

        if (options.PathSegment is { } segment && !IsPathSegment(segment))
        {
            failures.Add(
                $"{nameof(MultiTenancyOptions.PathSegment)} '{segment}' must be one path segment of URL-unreserved " +
                "characters that is not made of dots alone.");
        }

        failures.AddRange(
            from tenant in options.Tenants
            where !IsPathSegment(tenant.Id)
            select $"The tenant id '{tenant.Id}' must be one path segment of URL-unreserved characters that is " +
                   "not made of dots alone.");

        failures.AddRange(
            from tenant in options.Tenants
            where !IsIssuer(tenant.Issuer)
            select $"The issuer '{tenant.Issuer}' of tenant '{tenant.Id}' must be an absolute URI with no query " +
                   "or fragment.");

        failures.AddRange(
            from tenant in options.Tenants
            from host in tenant.Hosts
            where !TenantHost.IsBindable(host)
            select $"The host '{host}' of tenant '{tenant.Id}' must be a host name without a port.");

        failures.AddRange(
            from tenant in options.Tenants
            group tenant by tenant.Id into same
            where same.Count() > 1
            select $"The tenant id '{same.Key}' is declared more than once.");

        failures.AddRange(
            from tenant in options.Tenants
            group tenant.Id by tenant.Issuer into same
            where same.Count() > 1
            select $"The issuer '{same.Key}' is declared by more than one tenant: {string.Join(", ", same)}.");

        failures.AddRange(
            from tenant in options.Tenants
            from host in tenant.Hosts
            where TenantHost.IsBindable(host)
            group tenant.Id by TenantHost.Normalize(host) into same
            where same.Distinct(StringComparer.Ordinal).Count() > 1
            select $"The host '{same.Key}' is bound to more than one tenant: {string.Join(", ", same.Distinct())}.");

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// Whether <paramref name="value"/> is one non-empty path segment that travels unencoded (RFC 3986 section
    /// 2.3) and is not <c>.</c> or <c>..</c>, which a server collapses before any routing sees them.
    /// </summary>
    private static bool IsPathSegment(string? value)
        => !string.IsNullOrEmpty(value) &&
           value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~') &&
           value.Any(c => c != '.');

    private static bool IsIssuer(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var issuer) &&
           string.IsNullOrEmpty(issuer.Query) &&
           string.IsNullOrEmpty(issuer.Fragment);
}
