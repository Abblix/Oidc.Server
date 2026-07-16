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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// The Vault / OpenBao Transit key custodian: performs the private operations for keys the OIDC provider
/// publishes public-only, which live inside Transit as non-exportable keys and never enter this process. The
/// published <c>kid</c> is the Transit key name, so the library addresses each operation by it. This custodian
/// supports the RSA algorithms a Transit RSA key serves; ECDH-ES agreement is unreachable, as it needs an EC key
/// this custodian does not provision.
/// </summary>
public sealed class VaultCustodian(VaultTransitClient client) : IKeyCustodian
{
    /// <inheritdoc />
    public async ValueTask<byte[]> SignAsync(
        string kid, string algorithm, byte[] data, CancellationToken cancellationToken)
    {
        // RSA signatures are already in JWS wire format (raw bytes); an EC key would sign ES* and need the
        // DER -> R||S conversion RFC 7518 Section 3.4 mandates, which this RSA custodian does not do.
        if (algorithm != SigningAlgorithms.RS256)
            throw new NotSupportedException(
                $"The Vault custodian signs {SigningAlgorithms.RS256} only; got '{algorithm}'.");

        return await client.SignAsync(kid, data, cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<byte[]?> UnwrapKeyAsync(
        string kid, string algorithm, JsonWebTokenHeader header, byte[] encryptedKey, CancellationToken cancellationToken)
    {
        // Transit's RSA decrypt uses OAEP-SHA256, which is exactly what RSA-OAEP-256 produces, so a standard JWE
        // ciphertext round-trips once the client frames it in Transit's envelope.
        if (algorithm != EncryptionAlgorithms.KeyManagement.RsaOaep256)
            throw new NotSupportedException(
                $"The Vault custodian unwraps {EncryptionAlgorithms.KeyManagement.RsaOaep256} only; got '{algorithm}'.");

        return await client.DecryptAsync(kid, encryptedKey, cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask<byte[]> AgreeKeyAsync(
        string kid, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
        => throw new NotSupportedException(
            "ECDH-ES key agreement needs an EC key; the Vault custodian provisions RSA keys only.");
}
