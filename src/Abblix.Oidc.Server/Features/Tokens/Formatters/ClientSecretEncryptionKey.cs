// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using static Abblix.Jwt.EncryptionAlgorithms;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// The symmetric key a client-addressed JWT is encrypted with, derived from the client's secret by OpenID Connect
/// Core 1.0 section 10.2: "The symmetric encryption key is derived from the client_secret value by using the left-most
/// bits of a truncated SHA-2 hash of the octets of the UTF-8 representation of the client_secret. For keys of 256 or
/// fewer bits, SHA-256 is used; for keys of 257-384 bits, SHA-384 is used; for keys of 385-512 bits, SHA-512 is used."
/// </summary>
/// <remarks>
/// It is the only source of a symmetric key: OpenID Connect Dynamic Client Registration 1.0 section 2 has the client's
/// JWK Set "MUST NOT contain private or symmetric key values", so an octet key found there is never encrypted to.
/// </remarks>
internal static class ClientSecretEncryptionKey
{
    private const int BitsPerByte = 8;
    private const int Aes128KeySize = 128 / BitsPerByte;
    private const int Aes192KeySize = 192 / BitsPerByte;
    private const int Aes256KeySize = 256 / BitsPerByte;
    private const int AesCbcHmacKeyParts = 2;

    /// <summary>
    /// Whether the key management algorithm is carried out with a symmetric key: one registered for octet keys, so the
    /// symmetric family is the one the registry of key management algorithms holds rather than a second list.
    /// </summary>
    /// <param name="encryptionAlgorithms">The registry of key management algorithms.</param>
    /// <param name="keyManagementAlgorithm">The algorithm asked about.</param>
    public static bool IsSymmetric(EncryptionAlgorithmsProvider encryptionAlgorithms, string keyManagementAlgorithm)
        => encryptionAlgorithms.IsRegisteredFor<OctetJsonWebKey>(keyManagementAlgorithm);

    /// <summary>
    /// Whether a JWT can be encrypted to a client under the key management algorithm at all: an asymmetric one to a key
    /// the client publishes, a symmetric one only where section 10.2 derives a key for it from the client secret.
    /// </summary>
    /// <remarks>
    /// <c>dir</c> is asked with the content encryption algorithm a client registering none is sent
    /// (<see cref="ClientJwtEncryption.DefaultContentEncryptionAlgorithm"/>), so it counts as servable.
    /// </remarks>
    /// <param name="encryptionAlgorithms">The registry of key management algorithms.</param>
    /// <param name="keyManagementAlgorithm">The algorithm asked about.</param>
    public static bool CanBeServed(EncryptionAlgorithmsProvider encryptionAlgorithms, string keyManagementAlgorithm)
        => !IsSymmetric(encryptionAlgorithms, keyManagementAlgorithm) ||
           SizeInBytes(keyManagementAlgorithm, ClientJwtEncryption.DefaultContentEncryptionAlgorithm) is not null;

    /// <summary>
    /// The length of the key section 10.2 derives for the algorithm, or null where it derives none: section 10.2 covers
    /// "the AES key wrapping or direct encryption algorithm used", so a password-based algorithm, or one a host added,
    /// has no key derived for it. Under <c>dir</c> the key is the content encryption key, so its length is that of
    /// <paramref name="contentEncryptionAlgorithm"/> (RFC 7518 sections 5.2.3 to 5.2.5 and 5.3).
    /// </summary>
    /// <param name="keyManagementAlgorithm">The registered key management algorithm.</param>
    /// <param name="contentEncryptionAlgorithm">The content encryption algorithm the JWT is encrypted with.</param>
    public static int? SizeInBytes(string keyManagementAlgorithm, string contentEncryptionAlgorithm)
        => keyManagementAlgorithm switch
        {
            KeyManagement.Aes128KW or KeyManagement.Aes128Gcmkw => Aes128KeySize,
            KeyManagement.Aes192KW or KeyManagement.Aes192Gcmkw => Aes192KeySize,
            KeyManagement.Aes256KW or KeyManagement.Aes256Gcmkw => Aes256KeySize,
            KeyManagement.Dir => ContentEncryptionKeySize(contentEncryptionAlgorithm),
            _ => null,
        };

    /// <summary>
    /// The length of the content encryption key <paramref name="contentEncryptionAlgorithm"/> takes, or null for a name
    /// a host registered beyond those of RFC 7518 section 5.1, whose length is not known here.
    /// </summary>
    private static int? ContentEncryptionKeySize(string contentEncryptionAlgorithm)
        => contentEncryptionAlgorithm switch
        {
            ContentEncryption.Aes128Gcm => Aes128KeySize,
            ContentEncryption.Aes192Gcm => Aes192KeySize,
            ContentEncryption.Aes256Gcm => Aes256KeySize,

            // RFC 7518 section 5.2.2.1: an AES-CBC-HMAC key is the MAC key followed by the encryption key, of one length
            ContentEncryption.Aes128CbcHmacSha256 => AesCbcHmacKeyParts * Aes128KeySize,
            ContentEncryption.Aes192CbcHmacSha384 => AesCbcHmacKeyParts * Aes192KeySize,
            ContentEncryption.Aes256CbcHmacSha512 => AesCbcHmacKeyParts * Aes256KeySize,
            _ => null,
        };

    /// <summary>
    /// The client secret a key is derived from, or null where the client has none the server can read: a public client
    /// is refused outright (section 10.2: "Symmetric encryption MUST NOT be used by public (non-confidential)
    /// Clients"), and a secret stored only as a hash, or expired, is passed over. Of several, the one expiring last (one
    /// that never expires before any other), as a client rotating its secret holds the newer one.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="now">The current time, against which a secret's expiry is judged.</param>
    public static string? SecretOf(ClientInfo client, DateTimeOffset now)
    {
        if (client.ClientType == ClientType.Public)
            return null;

        return client.ClientSecrets?
            .Where(secret => !(secret.ExpiresAt < now) && !string.IsNullOrEmpty(secret.Value))
            .MaxBy(secret => secret.ExpiresAt ?? DateTimeOffset.MaxValue)?
            .Value;
    }

    /// <summary>
    /// The key derived from <paramref name="clientSecret"/> for <paramref name="keyManagementAlgorithm"/>, of
    /// <paramref name="sizeInBytes"/> octets.
    /// </summary>
    /// <param name="clientSecret">The client secret.</param>
    /// <param name="keyManagementAlgorithm">The algorithm the key is declared for.</param>
    /// <param name="sizeInBytes">The key length, as <see cref="SizeInBytes"/> gives it.</param>
    public static OctetJsonWebKey Derive(string clientSecret, string keyManagementAlgorithm, int sizeInBytes)
    {
        var octets = Encoding.UTF8.GetBytes(clientSecret);
        var digest = sizeInBytes switch
        {
            <= SHA256.HashSizeInBytes => SHA256.HashData(octets),
            <= SHA384.HashSizeInBytes => SHA384.HashData(octets),
            <= SHA512.HashSizeInBytes => SHA512.HashData(octets),

            // Section 10.2: "If a symmetric key with greater than 512 bits is needed, a different method of deriving
            // the key from the client_secret would have to be defined by an extension"
            _ => throw new ArgumentOutOfRangeException(
                nameof(sizeInBytes), sizeInBytes, "No key longer than a SHA-512 digest is derived from a client secret"),
        };

        return new OctetJsonWebKey
        {
            Algorithm = keyManagementAlgorithm,
            Usage = PublicKeyUsages.Encryption,
            KeyValue = digest[..sizeInBytes],
        };
    }
}
