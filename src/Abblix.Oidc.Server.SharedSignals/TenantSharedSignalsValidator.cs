// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Refuses to start a multi-tenant server whose transmitter would share anything between tenants.
/// </summary>
/// <remarks>
/// Each part the transmitter keeps per tenant is checked as resolved, so a registration made after
/// <see cref="SharedSignalsMultiTenancyExtensions.AddSharedSignals"/> that replaced one is named rather than left
/// to serve every tenant alike.
/// </remarks>
/// <param name="serviceProvider">Resolves the transmitter's parts as the server will use them.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantSharedSignalsValidator(IServiceProvider serviceProvider)
    : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        // Read from their registration and answered alone: the store holding them cannot be built outside a
        // tenant once a declared stream needs a poll address, and every part checked below is built on that store.
        if (serviceProvider.GetService<IReadOnlyList<ConfiguredStream>>() is not null)
        {
            return ValidateOptionsResult.Fail(
                "Streams declared in configuration belong to no tenant, so a multi-tenant server cannot serve them; "
                + "let each tenant's receivers create their streams through the stream management API.");
        }

        var failures = new List<string>();
        Require<IStreamStore, TenantStreamStore>(failures);

        Require<ITransmitterIdentity, TenantTransmitterIdentity>(failures);
        Require<IPushDeliverySweep, TenantPushDeliverySweep>(failures);

        var transmitter = serviceProvider.GetRequiredService<SharedSignalsTransmitterOptions>();
        if (!Uri.TryCreate(transmitter.Issuer, UriKind.Absolute, out var issuerUri) || issuerUri.AbsolutePath != "/")
        {
            failures.Add(
                $"The transmitter's issuer '{transmitter.Issuer}' must name the host without a path under "
                + "multi-tenancy: each tenant's addresses are its paths put under the tenant's own issuer.");
        }
        else if (transmitter.JwksUri is { } jwksUri &&
                 Uri.Compare(jwksUri, issuerUri, UriComponents.SchemeAndServer, UriFormat.Unescaped,
                     StringComparison.OrdinalIgnoreCase) != 0)
        {
            failures.Add(
                $"The transmitter's key set address '{jwksUri}' must be on the issuer's host under multi-tenancy: "
                + "each tenant's key set is served at that path under the tenant's own issuer.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
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
           + $"{typeof(TPerTenant).Name}. Register it before AddMultiTenancy().";
}
