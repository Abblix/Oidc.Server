// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;

namespace Abblix.Jwt;

/// <summary>
/// The structural half of the <c>crit</c> rules from RFC 7515 Section 4.1.11, shared by the two
/// header kinds that can carry one.
/// </summary>
/// <remarks>
/// RFC 7516 Section 4.1.13 defines <c>crit</c> for a JWE by pointing straight back at the JWS
/// definition - "This Header Parameter MUST be understood and processed as defined in Section
/// 4.1.11 of [JWS]" - so the rules are literally the same rules, and duplicating them per header
/// kind would be duplicating a specification reference. Only the set of names a producer must not
/// list differs, because the registered parameters differ between a JWS and a JWE header.
/// </remarks>
internal static class CriticalHeaderValidation
{
    /// <summary>
    /// Header parameter names registered by RFC 7515 Section 4.1 (plus <c>crit</c> itself). Per
    /// Section 4.1.11 a producer MUST NOT list any of these in <c>crit</c>, which exists to name
    /// extensions.
    /// </summary>
    public static readonly IReadOnlySet<string> JwsReservedNames = new HashSet<string>(StringComparer.Ordinal)
    {
        JwtClaimTypes.Algorithm,
        JwtClaimTypes.KeyId,
        JwtClaimTypes.Type,
        JwtClaimTypes.ContentType,
        JwtClaimTypes.EncryptionAlgorithm,
        JwtClaimTypes.Critical,
        JwtClaimTypes.JwkSetUrl,
        JwtClaimTypes.JsonWebKeyHeader,
        JwtClaimTypes.X509Url,
        JwtClaimTypes.X509CertificateChain,
        JwtClaimTypes.X509Sha1Thumbprint,
        JwtClaimTypes.X509Sha256Thumbprint,
    };

    /// <summary>
    /// The same prohibition for a JWE protected header: everything RFC 7516 Section 4.1 registers,
    /// which adds <c>zip</c>, plus the algorithm-specific parameters RFC 7518 Sections 4.6 to 4.8
    /// register for ECDH-ES, AES GCM key wrapping and PBES2. None of these is an extension, so
    /// none may appear in <c>crit</c>.
    /// </summary>
    public static readonly IReadOnlySet<string> JweReservedNames = new HashSet<string>(JwsReservedNames, StringComparer.Ordinal)
    {
        JwtClaimTypes.CompressionAlgorithm,
        JwtClaimTypes.EphemeralPublicKey,
        JwtClaimTypes.AgreementPartyUInfo,
        JwtClaimTypes.AgreementPartyVInfo,
        JwtClaimTypes.KeyWrapInitializationVector,
        JwtClaimTypes.KeyWrapAuthenticationTag,
        JwtClaimTypes.Pbes2SaltInput,
        JwtClaimTypes.Pbes2IterationCount,
    };

    /// <summary>
    /// Reads <c>crit</c> from <paramref name="header"/> and applies every rule that does not depend
    /// on which extensions the host has registered: the parameter must parse, must not be the empty
    /// array, must not repeat a name, must not name a registered parameter, and every name it lists
    /// must actually be present in the header.
    /// </summary>
    /// <param name="header">The JOSE header to inspect.</param>
    /// <param name="reservedNames">The registered names for this header kind: <see cref="JwsReservedNames"/>
    /// or <see cref="JweReservedNames"/>.</param>
    /// <param name="crit">The declared names when the header carries a well-formed <c>crit</c>,
    /// otherwise <see langword="null"/> - which covers both "no <c>crit</c>" and "rejected", so
    /// callers must check the return value first.</param>
    /// <returns><see langword="null"/> when there is nothing to reject, otherwise the first
    /// violation in declaration order, so the message names the offending parameter rather than
    /// reporting that something somewhere was wrong.</returns>
    public static JwtValidationError? ValidateStructure(
        JsonWebTokenHeader header,
        IReadOnlySet<string> reservedNames,
        out IReadOnlyList<string>? crit)
    {
        crit = null;

        IReadOnlyList<string>? declared;
        try
        {
            // The accessor throws on a crit that is not an array of strings; that is a token defect,
            // not a programming error, so it becomes a validation verdict here.
            declared = header.Critical;
        }
        catch (JsonException)
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                "Invalid 'crit' header: must be a JSON array of strings");
        }

        if (declared is null)
            return null;

        if (declared.Count == 0)
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                "'crit' header must not be the empty array (RFC 7515 §4.1.11)");
        }

        var distinctNames = new HashSet<string>(declared, StringComparer.Ordinal);
        if (distinctNames.Count != declared.Count)
            return new JwtValidationError(JwtError.InvalidHeader, "'crit' header contains duplicate names");

        foreach (var name in declared)
        {
            if (reservedNames.Contains(name))
            {
                return new JwtValidationError(
                    JwtError.InvalidHeader,
                    $"'crit' header must not list standard JOSE header name: {name}");
            }

            if (!header.Json.ContainsKey(name))
            {
                return new JwtValidationError(
                    JwtError.InvalidHeader,
                    $"'crit' lists header name '{name}' that is not present in the JOSE header");
            }
        }

        crit = declared;
        return null;
    }
}
