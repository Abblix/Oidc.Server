// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a server whose storage, replay cache or budgets every tenant would share.
/// </summary>
/// <remarks>
/// The server registers each in the form keeping the tenants apart, over what is registered under
/// <see cref="TenantServiceKeys"/>. A registration made after it of the service itself - a host's own storage put
/// in place with <c>Replace</c> - takes the tenants' form away, and every tenant then reads the others' data or
/// spends their budget. A limiter registered for one tenant's budget that hands every tenant the same instance
/// does the same. Only the finished container can show either.
/// </remarks>
/// <param name="serviceProvider">The finished container.</param>
internal sealed class TenantServicesValidator(IServiceProvider serviceProvider) : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = new[]
            {
                Shared<IEntityStorage, TenantEntityStorage>(null),
                Shared<IReplayCache, TenantReplayCache>(null),
                SharedBudget<string>(CallerRateLimiters.AuthenticationFailures),
                SharedBudget<(string ClientId, string? Source)>(CallerRateLimiters.Introspection),
                SharedBudget<(string ClientId, string? Source)>(CallerRateLimiters.Revocation),
            }
            .OfType<string>()
            .ToList();

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private string? Shared<TService, TTenantForm>(string? key)
        where TService : class
        => serviceProvider.GetKeyedService<TService>(key) switch
        {
            null or TTenantForm => null,
            var replaced =>
                $"{typeof(TService).Name}{(key is null ? string.Empty : $" '{key}'")} resolves to " +
                $"{replaced.GetType().Name}, which every tenant would share: it was replaced after the server was " +
                $"registered. Register it under the key {nameof(TenantServiceKeys)}." +
                (key is null ? nameof(TenantServiceKeys.Shared) : $"{nameof(TenantServiceKeys.PerTenant)}(\"{key}\")") +
                " instead, and the server keeps each tenant's part of it apart.",
        };

    /// <remarks>
    /// The budget for one tenant is resolved twice, as two tenants would resolve it: one instance for both means
    /// the tenants spend one budget.
    /// </remarks>
    private string? SharedBudget<TResource>(string key)
    {
        if (Shared<PartitionedRateLimiter<TResource>, TenantPartitionedRateLimiter<TResource>>(key) is { } replaced)
            return replaced;

        var perTenant = TenantServiceKeys.PerTenant(key);
        if (serviceProvider.GetKeyedService<PartitionedRateLimiter<TResource>>(perTenant) is not { } first ||
            !ReferenceEquals(first, serviceProvider.GetKeyedService<PartitionedRateLimiter<TResource>>(perTenant)))
        {
            return null;
        }

        return $"The budget '{perTenant}' hands every tenant the same limiter, so the tenants would spend one budget: " +
               "register it with a factory or a type, as a transient service, so that each tenant is built one.";
    }
}
