// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// At host start, verifies each composed singular pipeline (client authenticators, the token / authorization /
/// end-session / registration / CIBA / device context validators, grant handlers, request fetchers and logout
/// notifiers) still resolves to its composite. A service registered for one of these contracts AFTER
/// <c>AddOidcCore</c> composed it — for example a bare <c>TryAddEnumerable&lt;ITokenContextValidator, MyValidator&gt;</c>
/// — shadows the composite on the singular resolve (last-wins), silently dropping the entire built-in pipeline with
/// no per-request symptom. This turns that silent weakening into a clear startup failure naming the contract.
/// Register custom implementations of these contracts before <c>AddOidcCore</c>, which composes each family once.
/// </summary>
internal sealed class ComposedPipelineIntegrityService(IServiceProvider serviceProvider) : IHostedService
{
    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var registry = serviceProvider.GetService<ComposedFamilyRegistry>();
        if (registry is null)
            return Task.CompletedTask;

        // Several composed contracts are Scoped, so resolve inside a scope rather than from the root provider.
        using var scope = serviceProvider.CreateScope();
        foreach (var (service, composite) in registry.Families)
        {
            object? resolved;
            try
            {
                resolved = scope.ServiceProvider.GetService(service);
            }
            catch (InvalidOperationException)
            {
                // The composite could not be constructed in this scope because a host-provided dependency is
                // absent. That is a separate configuration problem which surfaces on first use, and shadowing
                // cannot be evaluated without a resolvable composite, so skip this family rather than misreport it.
                continue;
            }

            if (resolved is not null && resolved.GetType() != composite)
                throw new InvalidOperationException(
                    $"The {service.Name} pipeline resolves to {resolved.GetType().Name} instead of its composite " +
                    $"{composite.Name}. A registration added for {service.Name} after AddOidcCore shadows the composed " +
                    "pipeline on the singular resolve (last-wins), silently dropping the built-in implementations. " +
                    $"Register custom {service.Name} implementations before AddOidcCore, which composes each family once.");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
