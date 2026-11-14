// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt;

/// <summary>
/// Checks a JWS signature under one key with the signature primitive registered for the algorithm and the key's type.
/// </summary>
/// <remarks>
/// A verification key usually comes from the issuer's JWK Set, so key material the platform cannot import is a key
/// the signature does not verify under rather than a fault: the validator still answers with a verdict, and a sibling
/// key of the same set can still verify the token.
/// </remarks>
/// <param name="logger">Records a candidate key the platform could not import.</param>
/// <param name="serviceProvider">Resolves the keyed signature primitives
/// (<see cref="ISignatureAlgorithm{TJsonWebKey}"/>) by algorithm.</param>
internal sealed partial class KeyedSignatureCheck(ILogger<KeyedSignatureCheck> logger, IServiceProvider serviceProvider)
{
    /// <summary>
    /// Verifies a signature using the appropriate signer based on the key type and algorithm.
    /// Resolves the correct ISignatureAlgorithm implementation from DI using the algorithm as key.
    /// </summary>
    /// <param name="key">The JSON Web Key to use for verification.</param>
    /// <param name="algorithm">The signing algorithm.</param>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; false when it is not, or when the key cannot be imported.</returns>
    public bool Verify(JsonWebKey key, string algorithm, byte[] data, byte[] signature)
    {
        if (!key.HasPublicKey)
        {
            LogUnimportableKey(key.KeyId, algorithm, "the key carries no public key material");
            return false;
        }

        try
        {
            return key switch
            {
                RsaJsonWebKey rsaKey => ValidateBy(rsaKey),
                EllipticCurveJsonWebKey ecKey when NamedCurves.Named(ecKey.Curve) is null
                    => Unimportable($"the curve {ecKey.Curve} is not supported"),
                EllipticCurveJsonWebKey ecKey => ValidateBy(ecKey),
                OctetJsonWebKey octetKey => ValidateBy(octetKey),
                _ => false,
            };
        }
        // Windows CNG reports a point off its curve as PlatformNotSupportedException wrapping the
        // CryptographicException other platforms throw.
        catch (Exception exception) when (exception is CryptographicException or PlatformNotSupportedException)
        {
            return Unimportable(exception.Message);
        }

        bool Unimportable(string reason)
        {
            LogUnimportableKey(key.KeyId, algorithm, reason);
            return false;
        }

        bool ValidateBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var algorithmSigner = serviceProvider.GetKeyedService<ISignatureAlgorithm<TJsonWebKey>>(algorithm);
            return algorithmSigner != null && algorithmSigner.Verify(jwk, data, signature);
        }
    }
}
