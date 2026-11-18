// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// A JWE whose parts decoded and whose protected header names both of its algorithms.
/// </summary>
/// <param name="Parts">The five decoded parts of the compact serialization.</param>
/// <param name="Header">The protected header.</param>
/// <param name="Algorithm">The key management algorithm the header names.</param>
/// <param name="EncryptionAlgorithm">The content encryption algorithm the header names.</param>
/// <param name="EncodedHeader">The protected header as it was sent, which the content encryption authenticates.
/// </param>
[ExternalInput]
internal sealed record JweEnvelope(
    byte[][] Parts,
    JsonWebTokenHeader Header,
    string Algorithm,
    string EncryptionAlgorithm,
    string EncodedHeader)
{
    /// <summary>
    /// Decodes a JWE's compact serialization and reads its protected header (RFC 7516 section 5.2, steps 1 to 5).
    /// </summary>
    public static Result<JweEnvelope, JwtValidationError> Read(string[] jwtParts)
        => JweCompactSerialization.Decode(jwtParts).Bind(decodedParts => ReadEnvelope(decodedParts, jwtParts[0]));

    /// <summary>
    /// The plaintext as the sender wrote it, inflated when the header names a compression: the last step of
    /// RFC 7516 section 5.2, taken only after the plaintext opened under its authentication tag.
    /// </summary>
    public Result<byte[], JwtValidationError> Uncompress(byte[] plaintext)
        => JweCompression.Uncompress(Header, plaintext);

    private static Result<JweEnvelope, JwtValidationError> ReadEnvelope(byte[][] decodedParts, string encodedHeader)
    {
        // RFC 7516 section 5.2, steps 3 and 4: the header is a completely valid JSON object, and the recipient
        // verifies "that the resulting JOSE Header does not contain duplicate Header Parameter names".
        if (!JoseJson.TryParseObject(decodedParts[0], out var headerObject))
            return new JwtValidationError(
                JwtError.InvalidToken,
                "Invalid JWE header: must be a JSON object without repeated member names");

        var header = new JsonWebTokenHeader(headerObject);

        var encryptionAlgorithm = header.EncryptionAlgorithm;
        if (encryptionAlgorithm == null)
            return new JwtValidationError(JwtError.InvalidToken, "Missing 'enc' algorithm in JWE header");

        var algorithm = header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidToken, "Missing 'alg' algorithm in JWE header");

        // RFC 7516 Section 4.1.13 gives a JWE the same 'crit' parameter as a JWS, by reference:
        // "This Header Parameter MUST be understood and processed as defined in Section 4.1.11 of
        // [JWS]." That section is unambiguous about the consequence of not understanding a listed
        // name: "If any of the listed extension Header Parameters are not understood and supported
        // by the recipient, then the JWS is invalid." This library understands no JWE extensions,
        // so any well-formed 'crit' here is a rejection.
        // The check sits ahead of key selection deliberately, per the RFC 7516 Section 5.2 order:
        // a critical extension may change what the following steps are supposed to mean, so nothing
        // may touch key material while its meaning is still unknown.
        if (CriticalHeaderValidation.ValidateStructure(
                header, CriticalHeaderValidation.JweReservedNames, out var crit) is { } criticalError)
        {
            return criticalError;
        }

        if (crit is { Count: > 0 })
        {
            // Deliberately NOT routed to the keyed ICriticalHeaderHandler registry that serves JWS.
            // That keyspace is keyed by bare parameter name, so a host registering a handler for a
            // JWS extension would silently make the same name acceptable on a JWE envelope, where
            // it means something else and where the handler was never written to run.
            return new JwtValidationError(
                JwtError.InvalidHeader,
                $"Unknown critical header parameter in JWE header: {crit[0]}");
        }

        // RFC 7516 section 5.2 step 5 refuses a parameter whose value the implementation cannot process, so a "zip"
        // other than the one this library inflates is refused here, ahead of the keys
        if (!JweCompression.IsSupported(header))
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                $"Unsupported 'zip' in JWE header: only '{JweCompression.Deflate}' is supported");
        }

        return new JweEnvelope(decodedParts, header, algorithm, encryptionAlgorithm, encodedHeader);
    }
}
