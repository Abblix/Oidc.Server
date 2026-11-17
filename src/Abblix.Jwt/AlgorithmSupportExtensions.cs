// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Frozen;

namespace Abblix.Jwt;

/// <summary>
/// Whether a key's material can carry out a JWS signing algorithm, one rule per algorithm (Specification).
/// </summary>
internal static class AlgorithmSupportExtensions
{
    /// <summary>
    /// What each algorithm demands of a key's material (Specification pattern, one rule per algorithm). An
    /// algorithm absent from the table - "none", or a name this library cannot perform - is met by no key.
    /// </summary>
    private static readonly FrozenDictionary<string, Func<JsonWebKey, bool>> KeyRequirements =
        new (string[] Algorithms, Func<JsonWebKey, bool> IsMetBy)[]
        {
            (
                [
                    SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
                    SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512,
                ],
                key => key.KeyType == JsonWebKeyTypes.Rsa
            ),
            ([SigningAlgorithms.ES256], key => key.IsCurve(EllipticCurveTypes.P256)),
            ([SigningAlgorithms.ES384], key => key.IsCurve(EllipticCurveTypes.P384)),
            ([SigningAlgorithms.ES512], key => key.IsCurve(EllipticCurveTypes.P521)),
            (
                [SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512],
                key => key.KeyType == JsonWebKeyTypes.Octet
            ),

            // JWE key management is not here: which key type an algorithm is carried out with is the registration
            // of its IKeyManagementAlgorithm<TJsonWebKey>, a host's included, and EncryptionAlgorithmsProvider.CanEncrypt
            // asks that registry
        }
        .SelectMany(rule => rule.Algorithms, (rule, algorithm) => KeyValuePair.Create(algorithm, rule.IsMetBy))
        .ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>
    /// Whether this key can carry out the given JWS signing algorithm, judged by the key's own material rather than
    /// by what it declares. A JWE key management algorithm is asked of
    /// <see cref="EncryptionAlgorithmsProvider.CanEncrypt"/>, which reads the registered algorithms.
    /// </summary>
    /// <remarks>
    /// RFC 7517 section 4.4 makes <c>alg</c> OPTIONAL, so a key may simply not say what it is for - and a key
    /// imported from an RSA certificate never does. Such a key is not "unknown", it is answerable: RFC 7518 section 3.1
    /// binds each algorithm to a key type, and section 3.4 binds each ECDSA algorithm to one curve. Asking the
    /// material is therefore exact, and it is the only question that matters at the point of use, since a
    /// declaration is a claim while the material is the fact.
    /// </remarks>
    /// <param name="key">The key to test.</param>
    /// <param name="algorithm">The JWS algorithm the caller needs.</param>
    /// <returns>True when the key's type, and for ECDSA its curve, match what the algorithm requires.</returns>
    internal static bool SupportsAlgorithm(this JsonWebKey key, string algorithm)
        => KeyRequirements.TryGetValue(algorithm, out var isMetBy) && isMetBy(key);

    /// <summary>Whether the key is an elliptic-curve key on exactly the named curve.</summary>
    private static bool IsCurve(this JsonWebKey key, string curve)
        => key is EllipticCurveJsonWebKey ec && ec.Curve == curve;
}
