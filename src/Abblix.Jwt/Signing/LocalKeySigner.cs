// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
