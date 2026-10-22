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
/// </remarks>
/// <param name="serviceProvider">Resolves the transmitter's parts as the server will use them.</param>
internal sealed class TenantSharedSignalsStartupCheck(IServiceProvider serviceProvider) : IHostedLifecycleService
{
    /// <inheritdoc />
    public Task StartingAsync(CancellationToken cancellationToken)
    {
        var failures = Failures();
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

    private List<string> Failures()
    {
        var failures = new List<string>();
        Require<IStreamStore, TenantConfiguredStreamStore>(failures);

        Require<ITransmitterIdentity, TenantTransmitterIdentity>(failures);
        Require<IPushDeliverySweep, TenantPushDeliverySweep>(failures);

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

    private void Require<TService, TPerTenant>(List<string> failures)
        where TService : notnull
    {
        var service = serviceProvider.GetRequiredService<TService>();
        if (service is not TPerTenant)
            failures.Add(Shared<TService, TPerTenant>(service));
    }

    private static string Shared<TService, TPerTenant>(object service)
        => $"{typeof(TService).Name} is {service.GetType().Name}, which every tenant would share; it is replaced "
           + $"after {nameof(SharedSignalsMultiTenancyExtensions.AddSharedSignals)}() rather than wrapped by "
           + $"{typeof(TPerTenant).Name}. Register it before "
           + $"{nameof(SharedSignalsMultiTenancyExtensions.AddSharedSignals)}().";
}
