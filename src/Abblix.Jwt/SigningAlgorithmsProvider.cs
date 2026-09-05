// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Signing;

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Provides access to the collection of signing algorithms supported by the JWT infrastructure.
/// Projects the set from the live keyed <see cref="ISignatureAlgorithm{TJsonWebKey}"/> registrations, so
/// discovery always reflects exactly the signers the host currently has registered - including
/// algorithms the host added or replaced - with no registration-time bookkeeping to keep in sync.
/// </summary>
/// <remarks>
/// The enumerated key types mirror the dispatch switch in <see cref="JsonWebTokenSigner"/>: a signer
/// registered for any other <see cref="JsonWebKey"/> subtype is unreachable at run time, so it is
/// deliberately not advertised. The enumeration order (none, RSA, EC, octet) is the order these
/// algorithms appear in the discovery document, which consumers read verbatim.
/// </remarks>
internal sealed class SigningAlgorithmsProvider(IServiceProvider serviceProvider)
{
    /// <summary>
    /// Gets the collection of signing algorithms supported for JWT creation and validation.
    /// Returns algorithm identifiers self-declared by the registered signers (e.g. "RS256", "ES384").
    /// </summary>
    public IEnumerable<string> Algorithms =>
        AlgorithmsFor<JsonWebKey>()
            .Concat(AlgorithmsFor<RsaJsonWebKey>())
            .Concat(AlgorithmsFor<EllipticCurveJsonWebKey>())
            .Concat(AlgorithmsFor<OctetJsonWebKey>())
            .Distinct();

    private IEnumerable<string> AlgorithmsFor<TJsonWebKey>() where TJsonWebKey : JsonWebKey
        => serviceProvider
            .GetKeyedServices<ISignatureAlgorithm<TJsonWebKey>>(KeyedService.AnyKey)
            .Select(signer => signer.Algorithm);
}
