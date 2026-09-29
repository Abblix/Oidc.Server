// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// A service <typeparamref name="TService"/>, under a key, kept per tenant by <typeparamref name="TWrapper"/>.
/// </summary>
/// <remarks>
/// Template Method: finding the registration, refusing one that is missing and checking the result at startup are
/// the same for every service; how the registration found is turned into the wrapper is the subclass's step.
/// </remarks>
/// <param name="key">The key the service is registered under, or null for an unkeyed one.</param>
/// <param name="required">
/// Whether the server always registers the service; one it registers only for an enabled endpoint is wrapped when
/// present.
/// </param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal abstract class TenantSeam<TService, TWrapper>(object? key, bool required) : ITenantSeam
    where TService : class
    where TWrapper : class, TService
{
    /// <summary>The key the service is registered under, or null for an unkeyed one.</summary>
    protected object? Key => key;

    /// <summary>The service as a refusal names it.</summary>
    protected string Name => key is null ? typeof(TService).Name : $"{typeof(TService).Name} '{key}'";

    /// <inheritdoc />
    public void Wrap(IServiceCollection services)
    {
        // The last registration, the one the container resolves
        for (var index = services.Count - 1; 0 <= index; index--)
        {
            if (services[index].ServiceType == typeof(TService) && Equals(services[index].ServiceKey, key))
            {
                WrapRegistration(services, index);
                return;
            }
        }

        if (required)
        {
            throw new InvalidOperationException(
                $"{nameof(MultiTenancyExtensions.AddMultiTenancy)}() must come after AddOidcServices() and the " +
                $"server's other Add* calls: {Name} is not registered yet, so its data cannot be kept per tenant.");
        }
    }

    /// <summary>
    /// Turns the registration at <paramref name="index"/> in <paramref name="services"/> into one resolving
    /// <typeparamref name="TWrapper"/>.
    /// </summary>
    protected abstract void WrapRegistration(IServiceCollection services, int index);

    /// <inheritdoc />
    public string? FindShared(IServiceProvider serviceProvider)
        => serviceProvider.GetKeyedService<TService>(key) switch
        {
            TWrapper => null,
            null when !required => null,
            _ => Name,
        };
}
