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
/// Checks a JWS signature under one key with the signature primitive registered for the algorithm and the key's type.
/// </summary>
/// <param name="serviceProvider">Resolves the keyed signature primitives
/// (<see cref="ISignatureAlgorithm{TJsonWebKey}"/>) by algorithm.</param>
internal sealed class KeyedSignatureCheck(IServiceProvider serviceProvider)
{
    /// <summary>
    /// Verifies a signature using the appropriate signer based on the key type and algorithm.
    /// Resolves the correct ISignatureAlgorithm implementation from DI using the algorithm as key.
    /// </summary>
    /// <param name="key">The JSON Web Key to use for verification.</param>
    /// <param name="algorithm">The signing algorithm.</param>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool Verify(JsonWebKey key, string algorithm, byte[] data, byte[] signature)
    {
        // Validate that key contains public key material for verification
        if (!key.HasPublicKey)
        {
            throw new InvalidOperationException(
                $"Signature verification requires public key material, but key (kid={key.KeyId}) contains no public key data.");
        }

        return key switch
        {
            RsaJsonWebKey rsaKey => ValidateBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => ValidateBy(ecKey),
            OctetJsonWebKey octetKey => ValidateBy(octetKey),
            _ => false,
        };

        bool ValidateBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var algorithmSigner = serviceProvider.GetKeyedService<ISignatureAlgorithm<TJsonWebKey>>(algorithm);
            return algorithmSigner != null && algorithmSigner.Verify(jwk, data, signature);
        }
    }
}
