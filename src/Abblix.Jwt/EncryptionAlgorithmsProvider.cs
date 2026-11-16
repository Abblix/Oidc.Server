// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Provides access to the collections of JWE algorithms supported by the JWT infrastructure.
/// Projects both sets - key-management algorithms (the JWE <c>alg</c>, e.g. "RSA-OAEP-256") and
/// content-encryption algorithms (the JWE <c>enc</c>, e.g. "A256GCM") - from the live keyed
/// <see cref="IKeyManagementAlgorithm{TJsonWebKey}"/> and <see cref="IContentEncryptionAlgorithm"/> registrations, so
/// discovery always reflects exactly the encryptors the host currently has registered - including
/// algorithms the host added or replaced - with no registration-time bookkeeping to keep in sync.
/// </summary>
/// <remarks>
/// The enumerated key types mirror the dispatch switch in <see cref="LocalKeyEncryptor"/>: an
/// encryptor registered for any other <see cref="JsonWebKey"/> subtype is unreachable at run time,
/// so it is deliberately not advertised. The enumeration order (RSA, EC, octet) is the order these
/// algorithms appear in the discovery document, which consumers read verbatim.
/// </remarks>
public sealed class EncryptionAlgorithmsProvider(IServiceProvider serviceProvider)
{
    /// <summary>
    /// Whether <paramref name="key"/> may be used with the JWE key management algorithm
    /// <paramref name="keyManagementAlgorithm"/>: it declares that algorithm or none, and an algorithm of that name is
    /// registered for the key's type. The registry answering this is the one <see cref="KeyManagementAlgorithms"/>
    /// lists and encryption and decryption dispatch to, so an algorithm a host registers is advertised, matched to its
    /// keys and carried out by one and the same registration.
    /// </summary>
    /// <remarks>
    /// RFC 8725 section 3.1: "each key MUST be used with exactly one algorithm, and this MUST be checked when the
    /// cryptographic operation is performed", so a key declaring another algorithm is refused; RFC 7517 section 4.4
    /// makes <c>alg</c> optional, so a key declaring none is judged by its type.
    /// </remarks>
    /// <param name="key">The key asked about.</param>
    /// <param name="keyManagementAlgorithm">The JWE <c>alg</c> it would be used with.</param>
    public bool CanPerform(JsonWebKey key, string keyManagementAlgorithm)
        => (key.Algorithm ?? keyManagementAlgorithm) == keyManagementAlgorithm && key switch
        {
            RsaJsonWebKey => IsRegistered<RsaJsonWebKey>(keyManagementAlgorithm),
            EllipticCurveJsonWebKey => IsRegistered<EllipticCurveJsonWebKey>(keyManagementAlgorithm),
            OctetJsonWebKey => IsRegistered<OctetJsonWebKey>(keyManagementAlgorithm),
            _ => false,
        };

    /// <summary>
    /// The content encryption algorithm registered under <paramref name="contentEncryptionAlgorithm"/>, or null where
    /// none is: the registered set is the allow-list of the <c>enc</c> values an inbound JWE may use.
    /// </summary>
    /// <param name="contentEncryptionAlgorithm">The JWE <c>enc</c>.</param>
    internal IContentEncryptionAlgorithm? FindContentEncryptionAlgorithm(string contentEncryptionAlgorithm)
        => serviceProvider.GetKeyedService<IContentEncryptionAlgorithm>(contentEncryptionAlgorithm);

    private bool IsRegistered<TJsonWebKey>(string keyManagementAlgorithm) where TJsonWebKey : JsonWebKey
        => serviceProvider.GetKeyedService<IKeyManagementAlgorithm<TJsonWebKey>>(keyManagementAlgorithm) is not null;

    /// <summary>
    /// Gets the supported JWE key-management algorithms (the <c>alg</c> values, e.g. "RSA-OAEP-256").
    /// </summary>
    public IEnumerable<string> KeyManagementAlgorithms =>
        KeyManagementAlgorithmsFor<RsaJsonWebKey>()
            .Concat(KeyManagementAlgorithmsFor<EllipticCurveJsonWebKey>())
            .Concat(KeyManagementAlgorithmsFor<OctetJsonWebKey>())
            .Distinct();

    /// <summary>
    /// Gets the supported JWE content-encryption algorithms (the <c>enc</c> values, e.g. "A256GCM").
    /// </summary>
    public IEnumerable<string> ContentEncryptionAlgorithms
        => serviceProvider
            .GetKeyedServices<IContentEncryptionAlgorithm>(KeyedService.AnyKey)
            .Select(encryptor => encryptor.Algorithm)
            .Distinct();

    private IEnumerable<string> KeyManagementAlgorithmsFor<TJsonWebKey>() where TJsonWebKey : JsonWebKey
        => serviceProvider
            .GetKeyedServices<IKeyManagementAlgorithm<TJsonWebKey>>(KeyedService.AnyKey)
            .Select(encryptor => encryptor.Algorithm);
}
