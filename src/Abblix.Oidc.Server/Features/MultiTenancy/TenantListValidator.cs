// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses to start a server whose settings declare a tenant any check of a tenant list refuses, or that could
/// serve no tenant at all.
/// </summary>
/// <param name="checks">The checks of a tenant list.</param>
/// <param name="serviceProvider">Resolves where the tenants are read from, which tells whether any can arrive while
/// the server runs. It is asked when the check runs rather than when this is built, because the server's own store
/// reads the very settings this check judges, and taking it here would make the settings depend on themselves.
/// </param>
public sealed class TenantListValidator(IEnumerable<ITenantsCheck> checks, IServiceProvider serviceProvider)
    : IValidateOptions<OidcOptions>
{
    // The periods System.Threading.PeriodicTimer accepts
    private static readonly TimeSpan ShortestPeriod = TimeSpan.FromMilliseconds(1);
    private static readonly TimeSpan LongestPeriod = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = TenantRefusal.AllOf(checks, options.Tenants, options).Select(refusal => refusal.Message).ToList();

        // Tenants come from these settings alone unless the host keeps them in a store of its own, which the tenant
        // manager writes to while the server runs; with none declared here the server could never serve a request
        if (options.Tenants.Count == 0 && serviceProvider.GetRequiredService<ITenantStore>() is OptionsTenantStore)
        {
            failures.Add(
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.Tenants)} declares no tenant, and the tenants come from " +
                "these settings alone, so the server could serve no request. Declare at least one tenant - a server " +
                "serving one issuer declares one - or register a store of tenants they can be added to.");
        }

        if (options.RefreshTenantsEvery < ShortestPeriod || options.RefreshTenantsEvery > LongestPeriod)
        {
            failures.Add(
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.RefreshTenantsEvery)} must lie between " +
                $"{ShortestPeriod} and {LongestPeriod}: it is how often the store of tenants is read again, by a " +
                "timer that accepts no other period.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
