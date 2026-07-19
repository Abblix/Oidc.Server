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
/// The in-process signing backend (<see cref="IDataSigner"/>): owns keys that carry private material and signs
/// with them in memory, dispatching to the keyed per-algorithm <see cref="ISignatureAlgorithm{TJsonWebKey}"/>.
/// It is one peer among the backends <see cref="CompositeSigner"/> routes across; a public-only key is not
/// its own (<see cref="CanSign"/> returns false), so such a key routes to an external backend or, when none
/// owns it, the composite fails closed.
/// </summary>
internal sealed class LocalKeySigner(IServiceProvider serviceProvider) : IDataSigner
{
    /// <summary>
    /// Owns any key that carries private material: in-process signing needs the private half in memory.
    /// </summary>
    public bool CanSign(JsonWebKey key) => key.HasPrivateKey;

    public Task<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        // LocalKeySigner owns only private-bearing keys (see CanSign). When no external backend is composed it
        // is resolved as the sole signer, so it enforces its own ownership here too: refuse a public-only key
        // and fail closed rather than sign with nothing.
        if (!key.HasPrivateKey)
            throw new InvalidOperationException(
                $"Signing requires private key material for key (kid={key.KeyId}); it carries none " +
                "and no external signer is configured.");

        var signature = key switch
        {
            RsaJsonWebKey rsaKey => SignBy(rsaKey, algorithm, data),
            EllipticCurveJsonWebKey ecKey => SignBy(ecKey, algorithm, data),
            OctetJsonWebKey octetKey => SignBy(octetKey, algorithm, data),
            _ => throw new InvalidOperationException($"No signer registered for key type: {key.GetType().Name}"),
        };

        return Task.FromResult(signature);
    }

    private byte[] SignBy<TJsonWebKey>(TJsonWebKey jwk, string algorithm, byte[] data)
        where TJsonWebKey : JsonWebKey
    {
        var signer = serviceProvider.GetRequiredKeyedService<ISignatureAlgorithm<TJsonWebKey>>(algorithm);
        return signer.Sign(jwk, data);
    }
}
