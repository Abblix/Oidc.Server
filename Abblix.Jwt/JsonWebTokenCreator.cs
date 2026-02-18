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

namespace Abblix.Jwt;

/// <summary>
/// Responsible for creating JSON Web Tokens (JWTs). This class provides functionality to issue JWTs based on given claims and keys.
/// </summary>
/// <remarks>
/// The class uses custom signing and encryption implementations to create JWTs.
/// It supports setting standard claims such as issuer, audience, and times, as well as custom claims
/// contained within the provided <see cref="JsonWebToken"/> instance.
/// </remarks>
/// <param name="signer">The JWT signer for creating signatures.</param>
/// <param name="encryptor">The JWT encryptor for creating encrypted tokens.</param>
/// <param name="signingAlgorithmsProvider">The provider for supported signing algorithms.</param>
internal sealed class JsonWebTokenCreator(
    IJsonWebTokenSigner signer,
    IJsonWebTokenEncryptor encryptor,
    SigningAlgorithmsProvider signingAlgorithmsProvider) : IJsonWebTokenCreator
{
    /// <summary>
    /// Gets the collection of signing algorithms supported for JWT creation.
    /// Dynamically determined from registered signers in the dependency injection container.
    /// </summary>
    public IEnumerable<string> SignedResponseAlgorithmsSupported => signingAlgorithmsProvider.Algorithms;

    /// <summary>
    /// Asynchronously issues a JWT based on the specified JsonWebToken, signing key, and optional encryption key.
    /// </summary>
    /// <param name="token">The JsonWebToken object containing the payload of the JWT.</param>
    /// <param name="signingKey">The signing key as a JsonWebKey to sign the JWT.</param>
    /// <param name="encryptionKey">Optional encryption key as a JsonWebKey to encrypt the JWT.</param>
    /// <param name="keyEncryptionAlgorithm">
    /// Key encryption algorithm for JWE. Defaults to RSA-OAEP-256.
    /// Specifies how the Content Encryption Key (CEK) is encrypted with the recipient's public key.
    /// Per RFC 7518 Section 4 (Key Management Algorithms).
    /// Common values: RSA-OAEP-256, RSA-OAEP, RSA1_5, ECDH-ES, A128KW, A256KW.
    /// Only used when encryptionKey is provided.
    /// </param>
    /// <param name="contentEncryptionAlgorithm">
    /// Content encryption algorithm for JWE. Defaults to A256CBC-HS512.
    /// Specifies how the JWT payload is encrypted using the CEK.
    /// Per RFC 7518 Section 5 (Content Encryption Algorithms).
    /// Common values: A256CBC-HS512, A128CBC-HS256, A256GCM, A128GCM.
    /// Only used when encryptionKey is provided.
    /// </param>
    /// <returns>A task that returns the JWT as a string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the specified date time values cause an overflow.</exception>
    /// <remarks>
    /// The method creates a JWT using custom implementation that supports multiple audiences.
    /// Supports both JWS (signed) and JWE (encrypted) tokens.
    /// </remarks>
    public Task<string> IssueAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        JsonWebKey? encryptionKey = null,
        string keyEncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        string contentEncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)
    {
        var jwtString = signer.Sign(token, signingKey);

        if (encryptionKey != null)
        {
            jwtString = encryptor.Encrypt(
                jwtString,
                encryptionKey,
                token.Header.Type,
                keyEncryptionAlgorithm,
                contentEncryptionAlgorithm);
        }

        return Task.FromResult(jwtString);
    }
}
