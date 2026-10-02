// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring the services every feature relies on.
/// </summary>
public static class CommonServiceCollectionExtensions
{
    /// <summary>
    /// Registers common services required by the application, like system clock, hashing services, etc.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> with the common services registered.</returns>
    public static IServiceCollection AddCommonServices(this IServiceCollection services)
    {
        services.TryAddSingleton<IUserConsentsProvider, NullConsentService>();
        services.Decorate<IUserConsentsProvider, PromptConsentDecorator>();

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IHashService, HashService>();
        services.TryAddKeyedSingleton<IBinarySerializer, JsonBinarySerializer>(nameof(JsonBinarySerializer));
        services.TryAddKeyedSingleton<IBinarySerializer, ProtobufSerializer>(nameof(ProtobufSerializer));
        services.TryAddSingleton<IBinarySerializer, CompositeBinarySerializer>();
        services.TryAddSingleton<IEntityStorage, DistributedCacheStorage>();

        // The next-poll instant of a polled request, kept apart from the request itself: a poll
        // writing the request back to note it overwrote whatever the approval had changed.
        services.TryAddSingleton<IPollScheduleStore, PollScheduleStore>();
        return services.AddJsonWebTokens();
    }
}
