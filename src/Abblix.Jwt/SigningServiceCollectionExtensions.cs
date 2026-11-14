// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Registers the JWS signature algorithms, keyed by 'alg'.
/// </summary>
internal static class SigningServiceCollectionExtensions
{
    /// <summary>
    /// Registers the signature algorithms <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/> enables by
    /// default.
    /// </summary>
    internal static IServiceCollection AddDefaultSignatureAlgorithms(this IServiceCollection services)
    {
        return services
            .AddNoneSignatureAlgorithm()
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS256)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS384)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS512)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS256)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS384)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS512)

            .AddSignatureAlgorithm<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES256)
            .AddSignatureAlgorithm<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES384)
            .AddSignatureAlgorithm<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES512)

            .AddSignatureAlgorithm<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS256)
            .AddSignatureAlgorithm<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS384)
            .AddSignatureAlgorithm<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS512);
    }
}
