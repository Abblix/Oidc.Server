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

using System.Text;
using System.Text.Json;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Seals a private key to the custodian's key-encryption key, and opens it again. The envelope is a JWE, so this
/// carries no cryptography of its own: it hands the work to the JWT seam the library already ships.
/// </summary>
/// <remarks>
/// A JWE is precisely the envelope this tier needs. It encrypts content under a Content Encryption Key and wraps
/// that CEK under the recipient's key, which read as a key envelope is: the private JWK under a data-encryption
/// key, and that key under the KEK. The asymmetry that makes it work is the same one that keeps tier (a)'s
/// encryption side local - sealing needs only the KEK's public half, so it runs in process, while opening needs
/// the private half and therefore routes to the custodian through <c>ExternalKeyDecryptor</c>, which is triggered
/// by the KEK being published public-only.
/// </remarks>
internal sealed class KeyEnvelope(IJsonWebTokenEncryptor encryptor)
{
    /// <summary>
    /// Encrypts <paramref name="privateKey"/> to <paramref name="kek"/>, returning the JWE to store.
    /// </summary>
    /// <param name="privateKey">The key to seal, private half included.</param>
    /// <param name="kek">The KEK version to seal to, public half only; its <c>kid</c> lands in the JWE header and
    /// is what later selects the version that opens the envelope.</param>
    /// <param name="keyWrapAlgorithm">The JWE <c>alg</c>: how the data-encryption key is wrapped under the KEK.</param>
    /// <param name="contentEncryptionAlgorithm">The JWE <c>enc</c>: how the key itself is encrypted.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The envelope, JWE compact serialization.</returns>
    public async Task<string> SealAsync(
        JsonWebKey privateKey,
        JsonWebKey kek,
        string keyWrapAlgorithm,
        string contentEncryptionAlgorithm,
        CancellationToken cancellationToken)
    {
        // Serialize the key including its private half: that is the whole point of the envelope. The polymorphic
        // converter keeps the concrete key type, so an RSA key round-trips as an RSA key.
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(privateKey);

        return await encryptor.EncryptAsync(
            plaintext,
            kek,
            tokenType: null,
            keyWrapAlgorithm,
            contentEncryptionAlgorithm,
            cancellationToken);
    }

    /// <summary>
    /// Opens an envelope, returning the private key it holds.
    /// </summary>
    /// <param name="jwe">The envelope, JWE compact serialization.</param>
    /// <param name="kekVersions">The KEK's versions, public half only. The decrypt selects among them by the
    /// <c>kid</c> in the envelope's header, so passing every version is what lets a KEK rotation need no
    /// re-wrapping: an older envelope still names the version that sealed it.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The private key.</returns>
    public async Task<JsonWebKey> OpenAsync(
        string jwe,
        IAsyncEnumerable<JsonWebKey> kekVersions,
        CancellationToken cancellationToken)
    {
        var result = await encryptor.DecryptAsync(jwe.Split('.'), kekVersions, cancellationToken);

        // A decrypt failure is deliberately indistinguishable from a wrong key upstream, which is right for an
        // inbound token and wrong here: at startup it means the key did not come up. The likeliest cause is an
        // operator retiring the KEK version this envelope names (Vault's min_decryption_version, or disabling the
        // version in Azure), which strands the ring while every running pod keeps working from memory. Say so,
        // rather than starting without keys.
        var plaintext = result.Match(
            bytes => bytes,
            error => throw new InvalidOperationException(
                $"Cannot open a key envelope: the custodian did not unwrap it ({error.ErrorDescription}). The KEK " +
                "version this envelope names may have been retired, which strands every key wrapped under it."));

        return JsonSerializer.Deserialize<JsonWebKey>(Encoding.UTF8.GetString(plaintext))
            ?? throw new InvalidOperationException("A key envelope opened to a null key.");
    }
}
