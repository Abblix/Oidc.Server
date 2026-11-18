// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Nonces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring nonces and DPoP.
/// </summary>
public static class DPoPServiceCollectionExtensions
{
    /// <summary>
    /// Registers the generic stateless-nonce service. The default
    /// <see cref="RollingHmacNonceService"/> implementation is shared across
    /// any feature that needs server-issued, time-bounded opaque tokens
    /// (DPoP-Nonce per RFC 9449 section 8 / section 9 is the current consumer; future
    /// candidates include state-parameter validation and challenge-response
    /// patterns). Idempotent via <c>TryAdd</c> so feature-level
    /// <c>Add*</c> methods can declare the dependency without contention.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection AddNonces(this IServiceCollection services)
    {
        services.TryAddSingleton<INonceService, RollingHmacNonceService>();
        return services;
    }

    /// <summary>
    /// Registers the OAuth 2.0 DPoP (RFC 9449) infrastructure: the proof
    /// validator, the JWT replay cache it depends on (via defensive
    /// <c>TryAdd</c> so DPoP-only deployments do not need to enable JWT Bearer
    /// just to get the cache), and the shared nonce-service via
    /// <see cref="AddNonces"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection AddDPoP(this IServiceCollection services)
    {
        services.TryAddSingleton<IProofValidator, ProofValidator>();
        services.AddReplayPrevention();
        return services.AddNonces();
    }
}
