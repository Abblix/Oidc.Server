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
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses to start a server that could serve no tenant, whose tenant store writer writes where its tenants are never
/// read, or whose tenants would share a service the server keeps apart for each: its replay cache or budgets, or the
/// signer of its security events.
/// </summary>
/// <remarks>
/// A started service rather than a check of the settings: it builds the services it judges, and a host's service
/// that reads the settings while it is built would wait on itself inside the check of those settings. It refuses
/// while the host announces the start, before any started service runs on what it judges.
/// </remarks>
/// <param name="serviceProvider">The finished container.</param>
/// <param name="options">The tenants the settings declare.</param>
/// <param name="store">Where the tenants are read from.</param>
internal sealed class TenantServicesStartupCheck(
    IServiceProvider serviceProvider,
    IOptions<OidcOptions> options,
    ITenantStore store) : IHostedLifecycleService
{
    /// <inheritdoc />
    public Task StartingAsync(CancellationToken cancellationToken)
    {
        var failures = new List<string>();

        // Tenants come from the settings alone unless the host keeps them in a store of its own, which the tenant
        // manager writes to while the server runs; with none declared the server could never serve a request
        if (options.Value.Tenants.Count == 0 && store is OptionsTenantStore)
        {
            failures.Add(
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.Tenants)} declares no tenant, and the tenants come from " +
                "these settings alone, so the server could serve no request. Declare at least one tenant - a server " +
                "serving one issuer declares one - or register a store of tenants they can be added to.");
        }

        // The tenant manager writes through the writer and then reads the store again, and the settings never hold what
        // it wrote: it would report a tenant created, changed or removed that the server does not serve as told
        // Asked whether one is registered rather than built, so a writer the host cannot build yet does not hide this
        if (store is OptionsTenantStore &&
            serviceProvider.GetService<IServiceProviderIsService>() is { } services &&
            services.IsService(typeof(ITenantStoreWriter)))
        {
            failures.Add(
                $"An {nameof(ITenantStoreWriter)} is registered, but the tenants come from " +
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.Tenants)}, which never holds what it writes, so a tenant " +
                $"changed through {nameof(ITenantManager)} would not be served as changed. Register an " +
                $"{nameof(ITenantStore)} of your own that reads what the writer writes, or remove the writer.");
        }

        failures.AddRange(new[]
            {
                Replaced<IReplayCache, TenantReplayCache>(null),
                Replaced<PartitionedRateLimiter<string>, TenantPartitionedRateLimiter<string>>(
                    CallerRateLimiters.AuthenticationFailures),
                Replaced<PartitionedRateLimiter<(string ClientId, string? Source)>,
                    TenantPartitionedRateLimiter<(string ClientId, string? Source)>>(CallerRateLimiters.Introspection),
                Replaced<PartitionedRateLimiter<(string ClientId, string? Source)>,
                    TenantPartitionedRateLimiter<(string ClientId, string? Source)>>(CallerRateLimiters.Revocation),
                SharedByEveryTenant<string>(CallerRateLimiters.AuthenticationFailures),
                SharedByEveryTenant<(string ClientId, string? Source)>(CallerRateLimiters.Introspection),
                SharedByEveryTenant<(string ClientId, string? Source)>(CallerRateLimiters.Revocation),
                SignerSharedByEveryTenant(),
            }
            .OfType<string>());

        if (failures.Count > 0)
            throw new OptionsValidationException(Options.DefaultName, typeof(OidcOptions), failures);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private string? Replaced<TService, TTenantForm>(string? key)
        where TService : class
        => serviceProvider.GetKeyedService<TService>(key) switch
        {
            null or TTenantForm => null,
            var replaced =>
                $"{(key is null ? NameOf(typeof(TService)) : $"The budget '{key}'")} resolves to " +
                $"{NameOf(replaced.GetType())}, which every tenant would share. Register it under the key " +
                $"{nameof(TenantServiceKeys)}." +
                (key is null ? nameof(TenantServiceKeys.Shared) : $"{nameof(TenantServiceKeys.PerTenant)}(\"{key}\")") +
                " instead, and the server keeps each tenant's part of it apart.",
        };

    /// <summary>
    /// Refuses a limiter registered for one tenant's budget that hands every tenant the same instance, so every
    /// tenant would spend one budget.
    /// </summary>
    private string? SharedByEveryTenant<TResource>(string budget)
    {
        var perTenant = TenantServiceKeys.PerTenant(budget);
        var first = serviceProvider.GetKeyedService<PartitionedRateLimiter<TResource>>(perTenant);
        if (first is null || !ReferenceEquals(first, serviceProvider.GetKeyedService<PartitionedRateLimiter<TResource>>(perTenant)))
            return null;

        return $"The limiter registered under {nameof(TenantServiceKeys)}.{nameof(TenantServiceKeys.PerTenant)}" +
               $"(\"{budget}\") is one instance every tenant would spend; register it with a factory or a type that " +
               "builds a new limiter every time it is resolved.";
    }

    /// <summary>
    /// Refuses a signer of security events that signs every tenant's alike: one key given for every tenant, or a
    /// signer of the host's own. A receiver that signs nothing - no signer can be built - starts.
    /// </summary>
    private string? SignerSharedByEveryTenant()
    {
        if (serviceProvider.GetService<IServiceProviderIsService>() is not { } services ||
            !services.IsService(typeof(ISecurityEventTokenSigner)))
        {
            return null;
        }

        if (serviceProvider.GetService<IOptions<SecurityEventsOptions>>()?.Value.SigningKeySource is not null)
        {
            return $"{nameof(SecurityEventsOptions)}.{nameof(SecurityEventsOptions.SigningKeySource)} gives one key " +
                   "for every tenant, so each tenant's security events would be signed alike. " +
                   $"Leave it unset and register {nameof(TenantSecurityEventTokenSigner)} as the " +
                   $"{nameof(ISecurityEventTokenSigner)}; " + SharedSignalsTransmitter;
        }

        return SignerOf(serviceProvider) is null or TenantSecurityEventTokenSigner
            ? null
            : $"{nameof(ISecurityEventTokenSigner)} is the host's own, which signs every tenant's security events " +
              $"alike. Register {nameof(TenantSecurityEventTokenSigner)} instead; " + SharedSignalsTransmitter;
    }

    /// <summary>
    /// What a host running a Shared Signals transmitter does instead, since signing per tenant is only one of the
    /// parts that transmitter has to keep apart.
    /// </summary>
    private const string SharedSignalsTransmitter =
        "a Shared Signals transmitter is made per tenant, its signer included, by AddSharedSignals() of " +
        "Abblix.Oidc.Server.SharedSignals on what AddOidcServices() returns.";

    /// <summary>
    /// The registered signer, or null where none can be built - as the one <c>AddSecurityEvents</c> registers
    /// refuses to be without a signing key, which is a receiver's case. Resolved as a request would, so a signer
    /// registered for a request is judged too, rather than failing to resolve from the root and passing.
    /// </summary>
    private static ISecurityEventTokenSigner? SignerOf(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        try
        {
            return scope.ServiceProvider.GetService<ISecurityEventTokenSigner>();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>A type's name without the arity a generic type's name carries.</summary>
    private static string NameOf(Type type)
        => type.Name.IndexOf('`') is var arity and >= 0 ? type.Name[..arity] : type.Name;
}
