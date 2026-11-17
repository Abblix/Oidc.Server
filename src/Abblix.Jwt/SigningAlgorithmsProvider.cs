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
/// Provides access to the collection of signing algorithms supported by the JWT infrastructure.
/// Projects the set from the live keyed <see cref="ISignatureAlgorithm{TJsonWebKey}"/> registrations, so
/// discovery always reflects exactly the signers the host currently has registered - including
/// algorithms the host added or replaced - with no registration-time bookkeeping to keep in sync.
/// </summary>
/// <remarks>
/// The enumerated key types mirror the dispatch by key type that signing and verification make: a signer
/// registered for any other <see cref="JsonWebKey"/> subtype is unreachable at run time, so it is
/// deliberately not advertised. The enumeration order (none, RSA, EC, octet) is the order these
/// algorithms appear in the discovery document, which consumers read verbatim.
/// </remarks>
public sealed class SigningAlgorithmsProvider(IServiceProvider serviceProvider)
{
    /// <summary>
    /// Whether <paramref name="key"/> may sign a JWS with <paramref name="algorithm"/>: it declares that
    /// algorithm or none, an algorithm of that name is registered for the key's type, and that algorithm accepts the
    /// key's material. The registry answering this is the one <see cref="Algorithms"/> lists and signing and
    /// verification dispatch to, so an algorithm is advertised, matched to its keys and carried out by one and the
    /// same registration.
    /// </summary>
    /// <remarks>
    /// RFC 8725 section 3.1: "each key MUST be used with exactly one algorithm, and this MUST be checked when the
    /// cryptographic operation is performed", so a key declaring another algorithm is refused; RFC 7517 section 4.4
    /// makes <c>alg</c> optional, and a key imported from a certificate never carries one, so a key declaring none is
    /// judged by its material. A JWE key management algorithm is asked of
    /// <see cref="EncryptionAlgorithmsProvider.CanEncrypt"/>, and <see cref="SigningAlgorithms.None"/> is carried out
    /// with no key, so no key signs with it.
    /// </remarks>
    /// <param name="key">The key asked about.</param>
    /// <param name="algorithm">The JWS <c>alg</c> it would be used with.</param>
    public bool CanSign(JsonWebKey key, string algorithm)
        => (key.Algorithm ?? algorithm) == algorithm && key switch
        {
            RsaJsonWebKey rsaKey => Accepts(rsaKey, algorithm),
            EllipticCurveJsonWebKey ellipticCurveKey => Accepts(ellipticCurveKey, algorithm),
            OctetJsonWebKey octetKey => Accepts(octetKey, algorithm),
            _ => false,
        };

    /// <summary>
    /// The first of <paramref name="algorithms"/> <paramref name="key"/> signs with, by <see cref="CanSign"/>, or null
    /// where it signs with none: the one it declares, or, for a key declaring none, as one taken from a certificate,
    /// the first its material performs.
    /// </summary>
    /// <param name="key">The key asked about.</param>
    /// <param name="algorithms">The JWS algorithms acceptable to the caller, in its order of preference.</param>
    public string? FirstSignedWith(JsonWebKey key, IEnumerable<string> algorithms)
        => algorithms.FirstOrDefault(algorithm => CanSign(key, algorithm));

    private bool Accepts<TJsonWebKey>(TJsonWebKey key, string algorithm) where TJsonWebKey : JsonWebKey
        => serviceProvider.GetKeyedService<ISignatureAlgorithm<TJsonWebKey>>(algorithm) is { } signer &&
           signer.Accepts(key);

    /// <summary>
    /// Gets the collection of signing algorithms supported for JWT creation and validation.
    /// Returns algorithm identifiers self-declared by the registered signers (e.g. "RS256", "ES384").
    /// </summary>
    public IEnumerable<string> Algorithms =>
        AlgorithmsFor<JsonWebKey>()
            .Concat(AlgorithmsFor<RsaJsonWebKey>())
            .Concat(AlgorithmsFor<EllipticCurveJsonWebKey>())
            .Concat(AlgorithmsFor<OctetJsonWebKey>())
            .Distinct();

    private IEnumerable<string> AlgorithmsFor<TJsonWebKey>() where TJsonWebKey : JsonWebKey
        => serviceProvider
            .GetKeyedServices<ISignatureAlgorithm<TJsonWebKey>>(KeyedService.AnyKey)
            .Select(signer => signer.Algorithm);
}
