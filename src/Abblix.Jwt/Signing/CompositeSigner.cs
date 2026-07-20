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
