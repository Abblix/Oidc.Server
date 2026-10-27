// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Refuses to start a server whose transmitter would share anything between tenants.
/// </summary>
/// <remarks>
/// Each part the transmitter keeps per tenant is checked as resolved, so a registration made after
/// <see cref="SharedSignalsMultiTenancyExtensions.AddSharedSignals"/> that replaced one is named rather than left
/// to serve every tenant alike. A started service rather than a check of the settings: it builds the parts it
/// judges, and a part that reads the settings while it is built would wait on itself inside their check. Streams
/// declared for the whole server are refused before it runs, by <see cref="ServerWideStreamsValidator"/>.
/// <para>
/// The streams a tenant declares are built into its store once the host has started, inside the tenant, as its first
/// request would build them, so a declaration no request could be served from stops the host rather than waiting for
/// that request. Not before: a host that maps its endpoints while it starts declares the poll address only then, and
/// the catalog's first reading stays where the host's own services expect it. A tenant the catalog does not hold yet
/// is left to its first request, unless the server's settings are its only tenants. The refusal therefore comes once
/// the server listens, from the host's start, so a host that catches that exception and runs on serves the refused
/// declarations.
/// </para>
/// </remarks>
/// <param name="serviceProvider">Resolves the transmitter's parts as the server will use them.</param>
internal sealed class TenantSharedSignalsStartupCheck(IServiceProvider serviceProvider) : IHostedLifecycleService
{
    /// <inheritdoc />
    public Task StartingAsync(CancellationToken cancellationToken)
    {
        Refuse(Failures());
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public async Task StartedAsync(CancellationToken cancellationToken)
    {
        if (serviceProvider.GetService<TenantConfiguredStreams>() is { } declared)
            Refuse(await DeclarationFailuresAsync(declared, cancellationToken));
    }

    private static void Refuse(List<string> failures)
    {
        if (failures.Count > 0)
            throw new OptionsValidationException(Options.DefaultName, typeof(OidcOptions), failures);
    }

    /// <inheritdoc />
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private List<string> Failures()
    {
        var failures = new List<string>();
        // Resolved where no tenant is served, the server's registrations answer with what serves no tenant; a part a
        // later registration replaced answers as itself, and would serve every tenant alike
        Require<IStreamStore, NoTenantStreamStore>(failures);
        Require<ITransmitterIdentity, NoTenantTransmitterIdentity>(failures);
        Require<IEventOutbox, NoTenantEventOutbox>(failures);
        Require<IPushDeliverySweep, TenantPushDeliverySweep>(failures);
        RequirePartitions(failures);

        var transmitter = serviceProvider.GetRequiredService<SharedSignalsTransmitterOptions>();
        if (!Uri.TryCreate(transmitter.Issuer, UriKind.Absolute, out var issuerUri) || issuerUri.AbsolutePath != "/")
        {
            failures.Add(
                $"The transmitter's issuer '{transmitter.Issuer}' must name the host without a path: "
                + "each tenant's addresses are its paths put under the tenant's own issuer.");
        }
        else if (transmitter.JwksUri is { IsAbsoluteUri: false } relativeJwksUri)
        {
            failures.Add(
                $"The transmitter's key set address '{relativeJwksUri}' must be absolute: each tenant's key set is "
                + "served at its path under the tenant's own issuer.");
        }
        else if (transmitter.JwksUri is { } jwksUri &&
                 Uri.Compare(jwksUri, issuerUri, UriComponents.SchemeAndServer, UriFormat.Unescaped,
                     StringComparison.OrdinalIgnoreCase) != 0)
        {
            failures.Add(
                $"The transmitter's key set address '{jwksUri}' must be on the issuer's host: "
                + "each tenant's key set is served at that path under the tenant's own issuer.");
        }

        return failures;
    }

    private async Task<List<string>> DeclarationFailuresAsync(
        TenantConfiguredStreams declared,
        CancellationToken cancellationToken)
    {
        var catalog = serviceProvider.GetRequiredService<ITenantCatalog>();
        var transmitters = serviceProvider.GetRequiredService<TenantTransmitters>();
        var onlySettings = serviceProvider.GetRequiredService<ITenantStore>() is OptionsTenantStore;

        var failures = new List<string>();
        foreach (var tenantId in declared.TenantIds)
        {
            if (await catalog.FindByIdAsync(tenantId, cancellationToken) is not { } tenant)
            {
                if (onlySettings)
                {
                    failures.Add(
                        $"Streams are declared for the tenant '{tenantId}', which the server's settings do not "
                        + "declare, so no request would ever be served them.");
                }

                continue;
            }

            try
            {
                transmitters.For(tenant);
            }
            catch (InvalidOperationException exception)
            {
                failures.Add($"Tenant '{tenantId}': {exception.Message}");
            }
        }

        return failures;
    }

    private void Require<TService, TPerTenant>(List<string> failures)
        where TService : notnull
    {
        var service = serviceProvider.GetRequiredService<TService>();
        if (service is not TPerTenant)
            failures.Add(Shared<TService, TPerTenant>(service));
    }

    /// <summary>
    /// Refuses a store every tenant shares that keeps no partitions while the host registered one that does: a store
    /// the host wrapped around it hides the partitions the tenants' streams are kept in.
    /// </summary>
    private void RequirePartitions(List<string> failures)
    {
        if (serviceProvider.GetService<PartitionedStreamStoreRegistration>() is not { } registered)
            return;

        var shared = serviceProvider.GetRequiredKeyedService<IStreamStore>(TenantTransmitters.SharedStoreKey);
        if (shared is IPartitionedStreamStore)
            return;

        failures.Add(
            $"The stream store registered is {registered.StoreType.Name}, which keeps each tenant's streams in a "
            + $"partition of its own, but the store every tenant shares is {shared.GetType().Name}, which keeps none, "
            + "so the tenants' streams kept in partitions would not be found. A store wrapping "
            + $"{registered.StoreType.Name} implements {nameof(IPartitionedStreamStore)} and returns the inner "
            + "store's partition wrapped; a store of your own in its place is registered without the call that "
            + $"registers {registered.StoreType.Name}.");
    }

    private static string Shared<TService, TPerTenant>(object service)
        => $"{typeof(TService).Name} is {service.GetType().Name}, which every tenant would share; it is replaced "
           + $"after {nameof(SharedSignalsMultiTenancyExtensions.AddSharedSignals)}() rather than wrapped by "
           + $"{typeof(TPerTenant).Name}. Register it before "
           + $"{nameof(SharedSignalsMultiTenancyExtensions.AddSharedSignals)}().";
}
