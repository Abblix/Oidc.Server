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

using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Default <see cref="ICryptoRouter"/>: routes signing to the in-process keyed
/// <see cref="IDataSigner{TJsonWebKey}"/> when the key carries private material, and fails closed for a
/// public-only key. The external (key-custodian) branch is introduced together with the remote-signing
/// port, so this default is byte-identical to the previous in-process dispatch.
/// </summary>
/// <param name="serviceProvider">Resolves the keyed byte-primitive signer by algorithm.</param>
internal sealed class CryptoRouter(IServiceProvider serviceProvider) : ICryptoRouter
{
    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(
        JsonWebKey signingKey,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        // The absence of private material is exactly what will route to an external signer once one is
        // wired; until then a public-only signing key fails closed here rather than silently producing
        // nothing. This is the single home of the "sign requires the private half" rule (moved out of
        // JsonWebTokenSigner), so the same invariant will govern the shared protected-data seal.
        if (!signingKey.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"Signing requires private key material for key (kid={signingKey.KeyId}); it carries none " +
                "and no external signer is configured.");
        }

        // Secret material present: sign in process with the keyed primitive (the unchanged path).
        return new ValueTask<byte[]>(SignLocally(signingKey));

        byte[] SignLocally(JsonWebKey key) => key switch
        {
            RsaJsonWebKey rsaKey => SignBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => SignBy(ecKey),
            OctetJsonWebKey octetKey => SignBy(octetKey),
            _ => throw new InvalidOperationException($"No signer registered for key type: {key.GetType().Name}"),
        };

        byte[] SignBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var dataSigner = serviceProvider.GetRequiredKeyedService<IDataSigner<TJsonWebKey>>(algorithm);
            return dataSigner.Sign(jwk, data);
        }
    }
}
