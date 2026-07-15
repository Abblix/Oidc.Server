// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The key-recovery seam (<see cref="IContentKeyDecryptor"/>) as a composition of decryption backends: it holds every
/// registered backend and, per call, routes to the first that owns the key. Ownership is decided by the key -
/// <see cref="LocalKeyDecryptor"/> owns keys that carry their private/secret material, external custodian
/// backends (<see cref="ExternalKeyDecryptor"/>) own their public-only keys - so in-process unwrap, one or more
/// custodians, and any combination coexist as peers. When no backend owns the key it returns null: a uniform
/// decryption failure (RFC 7516 §11.5), never a throw on the attacker-supplied token. The backends are keyed by
/// this composite's type so it enumerates them without resolving itself.
/// </summary>
internal sealed class CompositeContentKeyDecryptor(IEnumerable<IContentKeyDecryptor> backends) : IContentKeyDecryptor
{
    public bool CanDecrypt(JsonWebKey key) => backends.Any(backend => backend.CanDecrypt(key));

    public ValueTask<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken)
    {
        var owner = backends.FirstOrDefault(backend => backend.CanDecrypt(key));
        if (owner == null)
        {
            // No backend owns this key - a public-only key whose custodian was never wired lands here. Return a
            // uniform decryption failure (RFC 7516 §11.5), never a throw on the attacker-supplied token.
            return default;
        }

        return owner.DecryptKeyAsync(header, key, algorithm, encryptedKey, cancellationToken);
    }
}
