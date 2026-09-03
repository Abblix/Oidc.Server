// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The key-recovery seam (<see cref="IContentKeyDecryptor"/>) as a composition of decryption backends: it holds every
/// registered backend and, per call, routes to the first that owns the key. Ownership is decided by the key -
/// <see cref="LocalKeyDecryptor"/> owns keys that carry their private/secret material, external custodian
/// backends (<see cref="ExternalKeys.ExternalKeyDecryptor"/>) own their public-only keys - so in-process unwrap, one or more
/// custodians, and any combination coexist as peers. When no backend owns the key it fails loud: a key with no
/// decryption path is a misconfiguration, not a ciphertext-dependent decryption failure (which a backend returns
/// as null per RFC 7516 section 11.5). The backends are keyed by this composite's type so it enumerates them without
/// resolving itself.
/// </summary>
internal sealed class CompositeDecryptor(IEnumerable<IContentKeyDecryptor> backends) : IContentKeyDecryptor
{
    public bool CanDecrypt(JsonWebKey key) => backends.Any(backend => backend.CanDecrypt(key));

    public Task<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken)
    {
        var owner = backends.FirstOrDefault(backend => backend.CanDecrypt(key));
        if (owner != null)
            return owner.DecryptKeyAsync(header, key, algorithm, encryptedKey, cancellationToken);

        // No backend owns this key: a public-only key with no custodian wired is a misconfiguration, not a
        // decryption failure. The standard Local + custodian composition always has an owner (Local owns
        // private-bearing keys, the custodian backend owns public-only ones), so this is only reachable when a
        // host's custom backend set leaves a key uncovered. Fail loud rather than silently reject; the RFC 7516
        // section 11.5 uniform-null is for ciphertext-dependent decryption failures, which a backend returns.
        throw new InvalidOperationException(
            $"No decryption backend owns key (kid={key.KeyId}): it carries no secret material and no external " +
            "key custodian is wired to serve it.");
    }
}
