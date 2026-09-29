// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// A service <typeparamref name="TService"/>, under a key, kept per tenant by <typeparamref name="TWrapper"/>.
/// </summary>
/// <param name="key">The key the service is registered under, or null for an unkeyed one.</param>
/// <param name="required">
/// Whether the server always registers the service; one it registers only for an enabled endpoint is wrapped when
/// present.
/// </param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class TenantSeam<TService, TWrapper>(object? key = null, bool required = true) : ITenantSeam
    where TService : class
    where TWrapper : class, TService
{
    private string Name => key is null ? typeof(TService).Name : $"{typeof(TService).Name} '{key}'";

    /// <inheritdoc />
    public void Wrap(IServiceCollection services)
    {
        if (services.Any(descriptor => descriptor.ServiceType == typeof(TService) && Equals(descriptor.ServiceKey, key)))
        {
            services.DecorateKeyed<TService, TWrapper>(key);
        }
        else if (required)
        {
            throw new InvalidOperationException(
                $"{nameof(MultiTenancyExtensions.AddMultiTenancy)}() must come after AddOidcServices() and the " +
                $"server's other Add* calls: {Name} is not registered yet, so its data cannot be kept per tenant.");
        }
    }

    /// <inheritdoc />
    public string? FindShared(IServiceProvider serviceProvider)
        => serviceProvider.GetKeyedService<TService>(key) switch
        {
            TWrapper => null,
            null when !required => null,
            _ => Name,
        };
}
