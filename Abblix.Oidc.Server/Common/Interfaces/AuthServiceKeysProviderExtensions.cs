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

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Extension helpers for <see cref="IAuthServiceKeysProvider"/>.
/// </summary>
public static class AuthServiceKeysProviderExtensions
{
    /// <summary>
    /// Builds the public key set published at the JWKS endpoint: the signing keys unchanged, plus the
    /// server's asymmetric encryption public keys marked <c>use=enc</c> so a client can encrypt a request
    /// object or other inbound JWE to the server (RFC 9101). A symmetric server key has no public half and
    /// is omitted; only sanitized public halves are ever published, never private or secret material.
    /// </summary>
    /// <param name="provider">The provider of the service's signing and encryption keys.</param>
    /// <returns>The signing keys followed by the asymmetric encryption public keys.</returns>
    public static async Task<JsonWebKey[]> GetPublishedKeysAsync(this IAuthServiceKeysProvider provider)
    {
        var signingKeys = await provider.GetSigningKeys().ToArrayAsync();

        var encryptionKeys = await provider.GetEncryptionKeys()
            .Where(key => key.HasPublicKey)
            .Select(key => key with { Usage = PublicKeyUsages.Encryption })
            .ToArrayAsync();

        return [..signingKeys, ..encryptionKeys];
    }
}
