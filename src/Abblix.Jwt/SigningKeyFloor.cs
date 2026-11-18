// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Signing;

namespace Abblix.Jwt;

/// <summary>
/// The minimum key sizes RFC 7518 sets for signing, applied to the keys a signature failed under, so a log can
/// tell a key refused for its size from a signature that did not match, and to a key no algorithm chose, so it is
/// reported for its size rather than as missing.
/// </summary>
internal static class SigningKeyFloor
{
    /// <summary>
    /// How far a signing key falls short of the floor of the algorithm it declares, or, declaring none, of the least
    /// demanding algorithm of its family (RS256 for an RSA key, HS256 for a symmetric one), or null where it does not.
    /// </summary>
    /// <remarks>
    /// The question a key is asked once, at startup and wherever no key was found for an algorithm: a key below every
    /// floor of its family signs with nothing, so it is reported for what it is rather than as a key that is missing.
    /// </remarks>
    /// <param name="key">The signing key asked about.</param>
    public static (int Bits, int Floor)? Undersized(JsonWebKey key)
    {
        var algorithm = key.Algorithm ?? key switch
        {
            RsaJsonWebKey => SigningAlgorithms.RS256,
            OctetJsonWebKey => SigningAlgorithms.HS256,
            _ => null,
        };

        if (algorithm is null)
            return null;

        return UndersizedKeys([key], algorithm)
            .Select(found => ((int Bits, int Floor)?)(found.Bits, found.Floor))
            .FirstOrDefault();
    }

    /// <summary>
    /// The candidate keys that cannot carry the algorithm's nominal strength, with what each measures and
    /// what it would have to.
    /// </summary>
    /// <remarks>
    /// The floor is asked of the same constants the signers refuse by, so moving one moves both. What this
    /// cannot do is ask a signer WHY it returned false: that would be a change to
    /// <see cref="ISignatureAlgorithm{TKey}.Verify"/>, whose bool is exactly what makes an undersized key
    /// from a peer a signature that does not check out rather than a fault in the caller. The cost of that
    /// choice is here rather than hidden, and it now has TWO axes: a key type that grows a floor later is
    /// reported by nothing until it is added below, and so is an algorithm missing from the list the RSA
    /// arm gates on. Both symptoms are the silence this method exists to end, which is why the algorithm
    /// list is pinned against the one the refusal itself cites rather than kept by hand.
    /// </remarks>
    public static IEnumerable<(JsonWebKey Key, int Bits, int Floor)> UndersizedKeys(
        IEnumerable<JsonWebKey> candidates,
        string algorithm)
    {
        foreach (var key in candidates)
        {
            // Both arms are gated on the ALGORITHM having a floor, and that gating is the whole of it.
            // RFC 7518 states the 2048 four times, once per family, and Section 3.4 - ECDSA - states no
            // size requirement at all; an RSA key stays a candidate for any algorithm it does not
            // contradict, because a key declaring no "alg" is deliberately not filtered out. Ungated,
            // this reported "alg='ES256' requires 2048 (RFC 7518)" - a requirement that document does not
            // make - and said it of a key that failed for having no signer registered rather than for its
            // size. The shape that turned that from wrong into dangerous is an algorithm-confusion probe:
            // take the issuer's RSA public key, sign with HS256, and the log tells the operator the burst
            // is a retired key rather than an attack.
            //
            // RSA is measured from the modulus rather than from RSA.KeySize, for the reason
            // ModulusBitLength gives.
            (int Bits, int Floor)? measured = key switch
            {
                RsaJsonWebKey rsaKey
                    when KeySizeFloors.MinimumRsaKeyBitsFor(algorithm) is { } floor
                    => (rsaKey.ModulusBitLength(), floor),

                OctetJsonWebKey { KeyValue: { } keyValue }
                    when KeySizeFloors.MinimumHmacKeyBits(algorithm) is { } floor
                    => (keyValue.Length << 3, floor),

                _ => null,
            };

            if (measured is { } size && size.Bits < size.Floor)
            {
                yield return (key, size.Bits, size.Floor);
            }
        }
    }
}
