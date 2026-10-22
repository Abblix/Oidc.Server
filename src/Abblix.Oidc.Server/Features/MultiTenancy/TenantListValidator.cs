// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses to start a server whose settings declare a tenant any check of a tenant list refuses, or reread the
/// tenants at a period the timer cannot keep.
/// </summary>
/// <param name="checks">The checks of a tenant list.</param>
public sealed class TenantListValidator(IEnumerable<ITenantsCheck> checks)
    : IValidateOptions<OidcOptions>
{
    // The periods System.Threading.PeriodicTimer accepts
    private static readonly TimeSpan ShortestPeriod = TimeSpan.FromMilliseconds(1);
    private static readonly TimeSpan LongestPeriod = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = TenantRefusal.AllOf(checks, options.Tenants, options).Select(refusal => refusal.Message).ToList();

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
