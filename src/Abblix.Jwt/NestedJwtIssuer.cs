// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;

namespace Abblix.Jwt;

/// <summary>
/// Issues a token as a JWS, and as a Nested JWT (RFC 7519 section 11.2) when it is also encrypted: signed first,
/// then the signed token encrypted as the plaintext of a JWE.
/// </summary>
/// <param name="signer">Signs the token.</param>
/// <param name="encryptor">Encrypts the signed token.</param>
internal sealed class NestedJwtIssuer(IJsonWebTokenSigner signer, IJsonWebTokenEncryptor encryptor)
{
    /// <summary>Signs <paramref name="token"/>, and encrypts the result when an encryption key is given.</summary>
    /// <param name="token">The token to issue.</param>
    /// <param name="signingKey">The signing key, or <c>null</c> for an unsigned token.</param>
    /// <param name="encryptionKey">The recipient's key, or <c>null</c> to issue the JWS as it is.</param>
    /// <param name="keyEncryptionAlgorithm">The JWE key management algorithm.</param>
    /// <param name="contentEncryptionAlgorithm">The JWE content encryption algorithm.</param>
    public async Task<string> IssueAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        JsonWebKey? encryptionKey,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm)
    {
        // IssueAsync does not yet carry a CancellationToken: the external key-custodian ports that would
        // observe one arrive with remote signing / key-management, which is when it is threaded up from
        // the callers. In-process crypto ignores cancellation, so None is passed until then.
        var jwtString = await signer.SignAsync(token, signingKey, CancellationToken.None);

        if (encryptionKey != null)
        {
            // The encryptor is byte-oriented; wrap the inner JWS as its UTF-8 plaintext.
            jwtString = await encryptor.EncryptAsync(
                Encoding.UTF8.GetBytes(jwtString),
                encryptionKey,
                token.Header.Type,
                keyEncryptionAlgorithm,
                contentEncryptionAlgorithm,
                CancellationToken.None);
        }

        return jwtString;
    }
}
