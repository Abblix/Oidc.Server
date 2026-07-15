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

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Signing;

/// <summary>
/// The in-process <see cref="IDataSigner"/>: signs with a signing key whose private material is held in
/// memory, dispatching to the keyed per-algorithm <see cref="ISignatureAlgorithm{TJsonWebKey}"/>, and fails
/// closed when the key carries none. It is the terminal link of any signer chain: an external-key decorator
/// sits in front of it (see <see cref="ExternalKeySigner"/>), so a public-only key reaching this link is one
/// that no decorator claimed, which must not sign with nothing.
/// </summary>
internal sealed class LocalKeySigner(IServiceProvider serviceProvider) : IDataSigner
{
    public ValueTask<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        // Fail closed: local signing needs private material, and reaching the terminal link without it means
        // no external signer claimed this public-only key, so throw rather than sign with nothing.
        if (!key.HasPrivateKey)
            throw new InvalidOperationException(
                $"Signing requires private key material for key (kid={key.KeyId}); it carries none " +
                "and no external signer is configured.");

        byte[] signature = key switch
        {
            RsaJsonWebKey rsaKey => SignBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => SignBy(ecKey),
            OctetJsonWebKey octetKey => SignBy(octetKey),
            _ => throw new InvalidOperationException($"No signer registered for key type: {key.GetType().Name}"),
        };
        return new ValueTask<byte[]>(signature);

        byte[] SignBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var algorithmSigner = serviceProvider.GetRequiredKeyedService<ISignatureAlgorithm<TJsonWebKey>>(algorithm);
            return algorithmSigner.Sign(jwk, data);
        }
    }
}
