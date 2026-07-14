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
/// <see cref="IDataSigner{TJsonWebKey}"/> when the key carries private material, to the host-provided
/// <see cref="IExternalSigner"/> by <c>kid</c> when it does not, and fails closed when a public-only key
/// has no external signer configured. The in-process path is byte-identical to the previous dispatch.
/// </summary>
/// <param name="serviceProvider">Resolves the keyed byte-primitive signer by algorithm.</param>
/// <param name="externalSigner">Optional host port that signs with an external key custodian
/// (HSM/KMS/vault). Absent (null) means no external keys, so signing is served entirely in process. It is
/// an optional dependency with a null default, so the container passes null when the host registers no
/// port.</param>
internal sealed class CryptoRouter(
    IServiceProvider serviceProvider,
    IExternalSigner? externalSigner = null) : ICryptoRouter
{
    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(
        JsonWebKey signingKey,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        // Secret material present: sign in process with the keyed primitive (the unchanged path).
        if (signingKey.HasPrivateKey)
            return new ValueTask<byte[]>(SignLocally(signingKey));

        // No private material means the key is published public-only, its private half held by an
        // external custodian. Route to the host port by kid; the absence of private material, not a flag,
        // is what selects the remote path. This is the single home of that decision (moved out of
        // JsonWebTokenSigner), so the same invariant will govern the shared protected-data seal.
        if (externalSigner != null)
        {
            // The kid published in the token and JWKS IS the custodian's handle - no separate identifier
            // and no mapping - so an external key must carry one.
            var kid = signingKey.KeyId ?? throw new InvalidOperationException(
                "An external signing key must carry a 'kid': it is the key custodian's handle.");

            return externalSigner.SignAsync(kid, algorithm, data, cancellationToken);
        }

        // Fail closed: a public-only key with no external signer cannot sign.
        throw new InvalidOperationException(
            $"Signing requires private key material for key (kid={signingKey.KeyId}); it carries none " +
            "and no external signer is configured.");

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
