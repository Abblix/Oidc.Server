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
/// Refuses to start a server whose settings declare a tenant any check of a tenant list refuses.
/// </summary>
/// <param name="checks">The checks of a tenant list.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantListValidator(IEnumerable<ITenantsCheck> checks) : IValidateOptions<MultiTenancyOptions>
{
    // The periods System.Threading.PeriodicTimer accepts
    private static readonly TimeSpan ShortestPeriod = TimeSpan.FromMilliseconds(1);
    private static readonly TimeSpan LongestPeriod = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        var failures = (
            from check in checks
            from refusal in check.Check(options.Tenants)
            select refusal.Message
        ).ToList();

        if (options.RefreshEvery < ShortestPeriod || options.RefreshEvery > LongestPeriod)
        {
            failures.Add(
                $"{nameof(MultiTenancyOptions)}.{nameof(MultiTenancyOptions.RefreshEvery)} must lie between " +
                $"{ShortestPeriod} and {LongestPeriod}: it is how often the store of tenants is read again, by a " +
                "timer that accepts no other period.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
