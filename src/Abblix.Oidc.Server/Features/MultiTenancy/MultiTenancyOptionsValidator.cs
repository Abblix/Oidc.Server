// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a tenant list that would resolve a request to more than one tenant, or to none it names.
/// </summary>
public sealed class MultiTenancyOptionsValidator : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        var failures = new List<string>();

        if (options.PathSegment is { } segment && (segment.Length == 0 || segment.Contains('/')))
            failures.Add($"{nameof(MultiTenancyOptions.PathSegment)} must be one non-empty path segment.");

        failures.AddRange(
            from tenant in options.Tenants
            where string.IsNullOrEmpty(tenant.Id) || tenant.Id.Contains('/')
            select $"The tenant id '{tenant.Id}' must be one non-empty path segment.");

        failures.AddRange(
            from tenant in options.Tenants
            group tenant by tenant.Id into same
            where same.Count() > 1
            select $"The tenant id '{same.Key}' is declared more than once.");

        failures.AddRange(
            from tenant in options.Tenants
            from host in tenant.Hosts
            group tenant.Id by host.ToUpperInvariant() into same
            where same.Distinct(StringComparer.Ordinal).Count() > 1
            select $"The host '{same.Key}' is bound to more than one tenant: {string.Join(", ", same.Distinct())}.");

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
