// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt;

/// <summary>
/// Registers one JWS signature algorithm, keyed by 'alg'.
/// </summary>
internal static class SignatureAlgorithmServiceCollectionExtensions
{
    /// <summary>
    /// Registers the algorithm none, whose signer takes no algorithm parameter.
    /// </summary>
    internal static IServiceCollection AddNoneSignatureAlgorithm(this IServiceCollection services)
    {
        // NoneSigner is registered directly: it is the only signer whose constructor takes no
        // algorithm parameter, so the AddSignatureAlgorithm factory (which passes the algorithm as
        // a constructor override) cannot instantiate it.
        services.TryAddKeyedSingleton<ISignatureAlgorithm<JsonWebKey>, NoneSigner>(SigningAlgorithms.None);
        return services;
    }

    /// <summary>
    /// Registers a data signer implementation for a specific JWS signing algorithm.
    /// Signers handle the "alg" parameter in JWS headers (e.g., RS256, ES384, HS512).
    /// </summary>
    /// <typeparam name="TKey">The type of JSON Web Key this signer operates on (RsaJsonWebKey,
    /// EllipticCurveJsonWebKey, OctetJsonWebKey, etc.).</typeparam>
    /// <typeparam name="TSigner">The ISignatureAlgorithm implementation for creating/verifying digital
    /// signatures.</typeparam>
    /// <param name="services">The service collection to register the signer in.</param>
    /// <param name="algorithm">The JWS signing algorithm identifier (e.g., "RS256", "ES384", "HS512").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the signer as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the signer constructor via dependency injection override.
    /// TryAdd dedups by (service, key) first-wins, so a host pre-registration for the algorithm wins
    /// over the built-in default.
    /// </remarks>
    internal static IServiceCollection AddSignatureAlgorithm<TKey, TSigner>(
        this IServiceCollection services,
        string algorithm)
        where TKey: JsonWebKey
        where TSigner: ISignatureAlgorithm<TKey>
    {
        services.TryAddKeyedSingleton<ISignatureAlgorithm<TKey>>(
            algorithm,
            (sp, _) => sp.CreateService<TSigner>(Dependency.Override(algorithm)));
        return services;
    }
}
