// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Signing;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// An external-custodian signing backend (<see cref="IDataSigner"/>) that owns public-only signing keys and
/// routes their signing to the host <see cref="IKeyCustodian"/>, addressing it by the key's <c>kid</c>. It is
/// registered by <c>ComposeExternalKeyBackends</c>, which every placement call performs, alongside the decryption
/// backend, so one custodian serves both seams.
/// </summary>
internal sealed class ExternalKeySigner(IKeyCustodian custodian) : IDataSigner
{
    /// <summary>
    /// Owns any public-only key: its private half lives with the custodian, so it cannot be signed in process.
    /// </summary>
    public bool CanSign(JsonWebKey key) => !key.HasPrivateKey;

    public Task<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        // The kid published in the token and JWKS IS the custodian's handle - no separate identifier and no
        // mapping - so an external key must carry one.
        var keyId = key.KeyId ?? throw new InvalidOperationException(
            "An external signing key must carry a 'kid': it is the key custodian's handle.");

        return custodian.SignAsync(keyId, algorithm, data, cancellationToken);
    }
}
