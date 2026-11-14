// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Frozen;

namespace Abblix.Jwt;

/// <summary>
/// The smallest keys RFC 7518 permits, and the section stating each floor, so a refusal can cite the paragraph
/// that refused.
/// </summary>
public static class KeySizeFloors
{
    /// <summary>
    /// The RFC 7518 section stating the RSA key-size floor, for every algorithm that has one. Both the floor and
    /// the citation are read from this one table, so an algorithm cannot gain a floor without its section.
    /// </summary>
    private static readonly FrozenDictionary<string, string> RsaKeySizeSections = new Dictionary<string, string>
    {
        [SigningAlgorithms.RS256] = "Section 3.3",
        [SigningAlgorithms.RS384] = "Section 3.3",
        [SigningAlgorithms.RS512] = "Section 3.3",
        [SigningAlgorithms.PS256] = "Section 3.5",
        [SigningAlgorithms.PS384] = "Section 3.5",
        [SigningAlgorithms.PS512] = "Section 3.5",
        [EncryptionAlgorithms.KeyManagement.Rsa1_5] = "Section 4.2",
        [EncryptionAlgorithms.KeyManagement.RsaOaep] = "Section 4.3",
        [EncryptionAlgorithms.KeyManagement.RsaOaep256] = "Section 4.3",
    }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>
    /// The smallest RSA modulus RFC 7518 permits. Four sections state it, one per family: Section 3.3
    /// and Section 3.5 for signing, Section 4.2 and Section 4.3 for key encryption. Almost the same
    /// words - 3.3 and 4.3 govern several algorithms and say "these", 3.5 and 4.2 govern one and say
    /// "this". One number here, so the sites that enforce it cannot drift apart.
    /// </summary>
    public const int MinimumRsaKeyBits = 2048;

    /// <summary>
    /// The smallest RSA modulus RFC 7518 requires for <paramref name="algorithm"/>, in bits, or
    /// <c>null</c> when that document sets no size requirement for it.
    /// </summary>
    /// <remarks>
    /// The floor is per FAMILY, not per key type: Sections 3.3, 3.5, 4.2 and 4.3 each state it for their
    /// own algorithms, and Section 3.4 - ECDSA - states none at all. A caller reporting on a key has to
    /// ask about whatever algorithm the header named, and take "no floor here" for an answer, or it ends
    /// up citing a requirement that document does not make.
    /// </remarks>
    internal static int? MinimumRsaKeyBitsFor(string algorithm)
        => RsaKeySizeSections.ContainsKey(algorithm) ? MinimumRsaKeyBits : null;

    /// <summary>
    /// The smallest HMAC key RFC 7518 Section 3.2 permits for <paramref name="algorithm"/>, in bits, or
    /// <c>null</c> when the algorithm is not one of the HMAC family.
    /// </summary>
    /// <remarks>
    /// "A key of the same size as the hash output" is the rule, so the number is the algorithm's own.
    /// Null rather than a throw, because the two callers ask different questions: the signer knows it is
    /// an HMAC algorithm and turns null into its own refusal, while a caller REPORTING on a key needs to
    /// ask about any algorithm and take "no floor of this family" for an answer.
    /// </remarks>
    internal static int? MinimumHmacKeyBits(string algorithm) => algorithm switch
    {
        SigningAlgorithms.HS256 => 256,
        SigningAlgorithms.HS384 => 384,
        SigningAlgorithms.HS512 => 512,
        _ => null,
    };

    /// <summary>
    /// The RFC 7518 section that carries the key-size requirement for <paramref name="algorithm"/>.
    /// </summary>
    /// <remarks>
    /// A refusal has to send the operator to the paragraph that refused them. Sections 3 and 4 are
    /// container headings and state no size requirement at all, so citing either leaves the reader
    /// looking at a table of algorithm names and no MUST - which reads as the library inventing the rule.
    /// </remarks>
    /// <exception cref="ArgumentException">The algorithm is not one this library enforces a floor for.</exception>
    public static string RsaSectionFor(string algorithm) => SectionOrNull(algorithm)
        ?? throw new ArgumentException($"No RSA key-size section is known for {algorithm}.", nameof(algorithm));

    /// <summary>
    /// The WHOLE citation phrase, ready to drop into a refusal message - "per RFC 7518 Section 3.3", or
    /// "for RSA signatures" when the algorithm has no section of its own.
    /// </summary>
    /// <remarks>
    /// Two differences from <see cref="RsaSectionFor"/>, and both matter at a call site. This one never
    /// throws for a non-null algorithm, because an unknown algorithm must not replace the refusal the
    /// operator was about to read with a complaint about the citation - and it is reachable, since an RSA
    /// key carrying no <c>alg</c> resolves to <c>SigningAlgorithms.None</c>. And this one carries the words
    /// "per RFC 7518" itself, where <see cref="RsaSectionFor"/> returns the bare section and leaves them to the
    /// caller. Interpolate this one into a sentence that writes them too and the message says them twice.
    /// </remarks>
    public static string RsaSectionForOrNothing(string algorithm)
        => SectionOrNull(algorithm) is { } section ? $"per RFC 7518 {section}" : "for RSA signatures";

    private static string? SectionOrNull(string algorithm)
        => RsaKeySizeSections.GetValueOrDefault(algorithm);
}
