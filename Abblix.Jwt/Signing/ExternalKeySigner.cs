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
/// An external-custodian signing backend (<see cref="IDataSigner"/>) that owns public-only signing keys and
/// routes their signing to the host <see cref="IKeyCustodian"/>, addressing it by the key's <c>kid</c>. It is
/// registered by <c>AddKeyCustodian</c> alongside the decryption backend, so one custodian serves both seams.
/// </summary>
internal sealed class ExternalKeySigner(IKeyCustodian custodian) : IDataSigner
{
    /// <summary>
    /// Owns any public-only key: its private half lives with the custodian, so it cannot be signed in process.
    /// </summary>
    public bool CanSign(JsonWebKey key) => !key.HasPrivateKey;

    public ValueTask<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        // The kid published in the token and JWKS IS the custodian's handle - no separate identifier and no
        // mapping - so an external key must carry one.
        var kid = key.KeyId ?? throw new InvalidOperationException(
            "An external signing key must carry a 'kid': it is the key custodian's handle.");

        return custodian.SignAsync(kid, algorithm, data, cancellationToken);
    }
}
