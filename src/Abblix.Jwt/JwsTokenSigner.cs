// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt.Signing;

namespace Abblix.Jwt;

/// <summary>
/// The signing side of <see cref="JsonWebTokenSigner"/>: encodes a token and signs it through the signing seam.
/// </summary>
/// <param name="dataSigner">The signing seam that produces the JWS signature bytes: in process for a
/// private-bearing key, or via an external key custodian for a public-only one. Routing local-vs-custodian
/// and the fail-closed rule live behind this seam, not in the token signer.</param>
internal sealed class JwsTokenSigner(IDataSigner dataSigner)
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    /// <summary>
    /// Creates a signed JSON Web Signature (JWS) token.
    /// </summary>
    public async Task<string> SignAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        CancellationToken cancellationToken = default)
    {
        var headerAlgorithm = token.Header.Algorithm;

        // Validate consistency between header algorithm and signing key
        if (signingKey == null)
        {
            // No signing key provided - always use "none" regardless of header
            // The signingKey parameter is authoritative for what actually happens
            token.Header.Algorithm = SigningAlgorithms.None;
            token.Header.KeyId = null;

            // Encode header and payload
            return $"{EncodeJson(token.Header.Json)}.{EncodeJson(token.Payload.Json)}.";
        }

        // Signing key provided - validate consistency and determine algorithm
        var keyAlgorithm = signingKey.Algorithm;

        // Validate: if both header and key specify algorithms, they must match
        if (headerAlgorithm != null && keyAlgorithm != null && headerAlgorithm != keyAlgorithm)
        {
            throw new InvalidOperationException(
                $"Algorithm mismatch: token header specifies '{headerAlgorithm}' " +
                $"but signing key specifies '{keyAlgorithm}'.");
        }

        // Validate: if header explicitly says "none" but we have a signing key, that's contradictory
        if (headerAlgorithm == SigningAlgorithms.None)
        {
            throw new InvalidOperationException(
                $"Token header explicitly specifies unsigned algorithm '{SigningAlgorithms.None}' " +
                "but a signing key was provided.");
        }

        var algorithm = keyAlgorithm ?? headerAlgorithm ?? SigningAlgorithms.None;

        token.Header.Algorithm = algorithm;
        token.Header.KeyId = signingKey.KeyId;

        // Encode header and payload
        var signingInput = $"{EncodeJson(token.Header.Json)}.{EncodeJson(token.Payload.Json)}";
        var signingBytes = Encoding.UTF8.GetBytes(signingInput);

        // Delegate the private operation to the signing seam: it signs in process for a private-bearing key
        // and routes to an external custodian for a public-only one, failing closed when neither applies.
        var signature = await dataSigner.SignAsync(signingKey, algorithm, signingBytes, cancellationToken);

        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// Encodes a JSON object to base64url string for JWT usage.
    /// </summary>
    private static string EncodeJson(JsonObject json)
    {
        var bytes = Encoding.UTF8.GetBytes(json.ToJsonString(Options));
        return Base64Url.EncodeToString(bytes);
    }
}
