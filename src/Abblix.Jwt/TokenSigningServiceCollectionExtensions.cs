// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt;

/// <summary>
/// Registers the token signer and the parts it is composed of.
/// </summary>
internal static class TokenSigningServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IJsonWebTokenSigner"/> with its signing and verifying sides. A host's own signer wins, and
    /// then the parts are registered but never asked for.
    /// </summary>
    internal static IServiceCollection AddTokenSigning(this IServiceCollection services)
    {
        services.TryAddSingleton<IJsonWebTokenSigner, JsonWebTokenSigner>();
        services.TryAddSingleton<JwsTokenSigner>();
        services.TryAddSingleton<JwsSignatureVerifier>();
        services.TryAddSingleton<KeyedSignatureCheck>();
        return services;
    }
}
