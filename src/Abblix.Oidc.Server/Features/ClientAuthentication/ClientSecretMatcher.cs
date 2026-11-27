// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Utils;
using CryptographicOperations = System.Security.Cryptography.CryptographicOperations;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Finds the stored secrets of a client a presented secret is: the one comparison both the token endpoint's
/// authentication and an RFC 7592 update carrying the client's secret make.
/// </summary>
/// <param name="hashService">Hashes the presented secret, since only its hashes are stored.</param>
internal sealed class ClientSecretMatcher(IHashService hashService)
{
    /// <summary>
    /// The secrets of <paramref name="client"/> whose stored hash is the hash of <paramref name="secret"/>, expired ones
    /// included.
    /// </summary>
    /// <param name="client">The client owning the secrets.</param>
    /// <param name="secret">The secret presented.</param>
    public IEnumerable<ClientSecret> FindMatching(ClientInfo client, [Credential] string secret)
        => FindMatching(client, clientSecret => clientSecret.Sha512Hash, HashAlgorithm.Sha512, secret)
            .Concat(FindMatching(client, clientSecret => clientSecret.Sha256Hash, HashAlgorithm.Sha256, secret));

    private IEnumerable<ClientSecret> FindMatching(
        ClientInfo client,
        Func<ClientSecret, byte[]?> hashSelector,
        HashAlgorithm hashAlgorithm,
        [Credential] string secretValue)
    {
        var validSecretHashes =
            from clientSecret in client.ClientSecrets ?? []
            let secretHash = hashSelector(clientSecret)
            where secretHash != null
            select (clientSecret, secretHash);

        // Hashed lazily, so a client holding no hash of this kind costs no hashing
        byte[]? hash = null;
        foreach (var (clientSecret, validSecretHash) in validSecretHashes)
        {
            hash ??= hashService.Sha(hashAlgorithm, secretValue);

            // Constant-time compare of the secret hashes (both are fixed-length digests of the
            // same algorithm) so the comparison does not leak a timing oracle on the hash.
            if (CryptographicOperations.FixedTimeEquals(validSecretHash, hash))
                yield return clientSecret;
        }
    }
}
