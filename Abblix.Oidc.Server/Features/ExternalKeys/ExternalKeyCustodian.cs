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

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Adapts an <see cref="IExternalKeyStore"/> to the <see cref="IKeyCustodian"/> seam: it performs the private
/// operations for keys the provider publishes public-only, addressed by the <c>kid</c> (which is the store's key
/// name). One custodian serves any store, so the Vault and Azure packages carry no custodian of their own.
/// </summary>
/// <remarks>
/// Scope is RSA today: the store's sign and unwrap are fixed to <c>RS256</c> and <c>RSA-OAEP-256</c> (the
/// operations both backends provision), so this custodian gates to exactly those and treats anything else as
/// unsupported. ECDH-ES agreement is unreachable, as it needs an EC key such a store does not provision. Widening
/// to other algorithms means threading the algorithm into <see cref="IExternalKeyStore"/> so each backend maps it,
/// and generalizing the public-key surface for EC.
/// </remarks>
public sealed class ExternalKeyCustodian(IExternalKeyStore store) : IKeyCustodian
{
    /// <inheritdoc />
    public async ValueTask<byte[]> SignAsync(
        string kid, string algorithm, byte[] data, CancellationToken cancellationToken)
    {
        // RSA signatures are already in JWS wire format; an EC key would sign ES* and need the DER -> R||S
        // conversion RFC 7518 Section 3.4 mandates, which an RSA store does not do. The store's sign is fixed to
        // RS256, so accepting any other algorithm would silently return an RS256 signature for it.
        if (algorithm != SigningAlgorithms.RS256)
            throw new NotSupportedException(
                $"The external key custodian signs {SigningAlgorithms.RS256} only; got '{algorithm}'.");

        return await store.SignAsync(kid, data, cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<byte[]?> UnwrapKeyAsync(
        string kid, string algorithm, JsonWebTokenHeader header, byte[] encryptedKey, CancellationToken cancellationToken)
    {
        // The store's unwrap is fixed to RSA-OAEP-256, so gate to exactly that for the same reason as signing.
        if (algorithm != EncryptionAlgorithms.KeyManagement.RsaOaep256)
            throw new NotSupportedException(
                $"The external key custodian unwraps {EncryptionAlgorithms.KeyManagement.RsaOaep256} only; got '{algorithm}'.");

        return await store.DecryptAsync(kid, encryptedKey, cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask<byte[]> AgreeKeyAsync(
        string kid, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
        => throw new NotSupportedException(
            "ECDH-ES key agreement needs an EC key; the external RSA key custodian does not provision one.");
}
