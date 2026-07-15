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

namespace Abblix.Jwt.Signing;

/// <summary>
/// An <see cref="IDataSigner"/> decorator that routes a public-only key's signing to a host
/// <see cref="ExternalSignHandler"/> (an HSM/KMS/vault callback), and delegates any key that carries private
/// material to the inner signer. The absence of private material (not a flag) selects the remote path, and
/// the key's <c>kid</c> IS the custodian's handle. Registered by the <c>AddExternalSigner</c> convenience;
/// a host that wants full control writes its own <see cref="IDataSigner"/> decorator instead.
/// </summary>
internal sealed class ExternalKeySigner(IDataSigner inner, ExternalSignHandler sign) : IDataSigner
{
    public ValueTask<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        if (key.HasPrivateKey)
            return inner.SignAsync(key, algorithm, data, cancellationToken);

        // The kid published in the token and JWKS IS the custodian's handle - no separate identifier and no
        // mapping - so an external key must carry one.
        var kid = key.KeyId ?? throw new InvalidOperationException(
            "An external signing key must carry a 'kid': it is the key custodian's handle.");

        return sign(kid, algorithm, data, cancellationToken);
    }
}
