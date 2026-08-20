// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Signing;

/// <summary>
/// The signing seam (<see cref="IDataSigner"/>) as a composition of signing backends: it holds every registered
/// backend and, per call, routes to the first that owns the key. Ownership is decided by the key, not the
/// algorithm - <see cref="LocalKeySigner"/> owns private-bearing keys, external custodian backends
/// (<see cref="ExternalKeys.ExternalKeySigner"/>) own their public-only keys - so in-process signing, one or more custodians,
/// and any combination coexist as peers. When no backend owns the key the seam fails closed: it throws rather
/// than emit an unsigned or empty signature (a public-only key whose custodian was never wired lands here). The
/// backends are keyed by this composite's type so it enumerates them without resolving itself.
/// </summary>
internal sealed class CompositeSigner(IEnumerable<IDataSigner> backends) : IDataSigner
{
    public bool CanSign(JsonWebKey key) => backends.Any(backend => backend.CanSign(key));

    public Task<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        var owner = backends.FirstOrDefault(backend => backend.CanSign(key));
        if (owner == null)
        {
            throw new InvalidOperationException(
                $"No signing backend owns key (kid={key.KeyId}): it carries no private material and no external " +
                "signer claims it. Register an external signer for this key, or supply one that carries private material.");
        }

        return owner.SignAsync(key, algorithm, data, cancellationToken);
    }
}
