// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Answers whether a client can be sent a JWT encrypted under the key management algorithm it registered, and with
/// which key: the one question both the formatter that encrypts the JWT and the security profile check that judges the
/// client ahead of it ask.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 section 10.2 names the key by the algorithm's family. An asymmetric algorithm encrypts to
/// what "MUST be a public key used for encryption published by the recipient in its JWK Set document"; a symmetric one
/// to the key "derived from the client_secret value" (<see cref="ClientSecretEncryptionKey"/>), and to nothing else.
/// <para>
/// Public, though nothing outside this library needs it, because the formatter that takes it is a public type with a
/// public constructor, which the container requires.
/// </para>
/// </remarks>
/// <param name="issuer">Decides whether the host performs an algorithm with a key and the profile admits it.</param>
/// <param name="clientKeysProvider">Supplies the encryption keys the client publishes.</param>
/// <param name="timeProvider">Supplies the time a client secret's expiry is judged against.</param>
public sealed class ClientEncryptionKeyResolver(
    ProfiledJwtIssuer issuer,
    IClientKeysProvider clientKeysProvider,
    TimeProvider timeProvider)
{
    /// <summary>
    /// The key a JWT for <paramref name="client"/> is encrypted to under <paramref name="keyManagementAlgorithm"/>, or
    /// null where there is none: the first published key that declares the algorithm or none, whose material carries it
    /// out, the host performs it with and <paramref name="profile"/> admits; for a symmetric algorithm, the key derived
    /// from the client secret, under the same conditions.
    /// </summary>
    /// <param name="profile">The controls the client is held to.</param>
    /// <param name="client">The client the JWT is addressed to.</param>
    /// <param name="keyManagementAlgorithm">The key management algorithm the client registered.</param>
    /// <param name="contentEncryptionAlgorithm">The content encryption algorithm the JWT is encrypted with, which fixes
    /// the length of a key used directly as the content encryption key.</param>
    public async Task<JsonWebKey?> ResolveAsync(
        SecurityProfileRequirements profile,
        ClientInfo client,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm)
    {
        if (!ClientSecretEncryptionKey.IsSymmetric(keyManagementAlgorithm))
        {
            return await clientKeysProvider.GetEncryptionKeys(client).FirstOrDefaultAsync(key =>
                Carries(key, keyManagementAlgorithm) && Usable(profile, key, keyManagementAlgorithm));
        }

        if (ClientSecretEncryptionKey.SizeInBytes(keyManagementAlgorithm, contentEncryptionAlgorithm) is not { } size ||
            ClientSecretEncryptionKey.SecretOf(client, timeProvider.GetUtcNow()) is not { } secret)
        {
            return null;
        }

        var derived = ClientSecretEncryptionKey.Derive(secret, keyManagementAlgorithm, size);
        return Usable(profile, derived, keyManagementAlgorithm) ? derived : null;
    }

    /// <summary>
    /// Whether a key the client publishes carries <paramref name="keyManagementAlgorithm"/>: it declares the algorithm
    /// or none, and its material carries it out.
    /// </summary>
    internal static bool Carries(JsonWebKey key, string keyManagementAlgorithm)
        => (key.Algorithm ?? keyManagementAlgorithm) == keyManagementAlgorithm &&
           key.SupportsAlgorithm(keyManagementAlgorithm);

    private bool Usable(SecurityProfileRequirements profile, JsonWebKey key, string keyManagementAlgorithm)
        => issuer.EncryptionAlgorithmFor(profile, key, keyManagementAlgorithm) is not null;
}
