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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Validates a DPoP proof JWT per RFC 9449 §4.2 / §4.3 covering structure, algorithm
/// whitelist, embedded-JWK shape, signature, and the request-binding claim triplet
/// (<c>htm</c>, <c>htu</c>, optional <c>ath</c>) plus <c>iat</c> window and <c>jti</c>
/// presence. Replay-cache and DPoP-Nonce checks layer on top of the returned
/// <see cref="Proof"/> in a separate slice.
/// </summary>
/// <remarks>
/// JWS signature verification delegates to the existing <see cref="IJsonWebTokenSigner"/>,
/// which resolves an <c>IDataSigner</c> by algorithm and runs the actual crypto. We pass
/// the JWK embedded in the proof header as the only candidate key, since DPoP carries
/// no <c>iss</c> claim against which an issuer-resolved key set could be looked up.
/// </remarks>
internal sealed class ProofValidator(
    IJsonWebTokenSigner signer,
    TimeProvider timeProvider) : IProofValidator
{
    private const string ExpectedTyp = "dpop+jwt";

    private static readonly IReadOnlySet<string> AllowedAlgorithms = new HashSet<string>(StringComparer.Ordinal)
    {
        SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
        SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512,
        SigningAlgorithms.ES256, SigningAlgorithms.ES384, SigningAlgorithms.ES512,
    };

    // Default iat tolerance until OidcOptions.Dpop.IatToleranceSeconds lands in #108.
    private static readonly TimeSpan IatTolerance = TimeSpan.FromSeconds(60);

    public async Task<Result<Proof, ProofError>> ValidateAsync(
        string proofJwt,
        string httpMethod,
        Uri requestUri,
        string? accessToken = null,
        CancellationToken cancellationToken = default)
    {
        var parts = proofJwt.Split('.');
        if (parts.Length != 3)
            return new ProofError("malformed_jwt", "Expected three dot-separated segments.");

        JsonObject? headerObj, payloadObj;
        try
        {
            var headerBytes = Base64Url.DecodeFromChars(parts[0]);
            var payloadBytes = Base64Url.DecodeFromChars(parts[1]);
            headerObj = JsonNode.Parse(headerBytes) as JsonObject;
            payloadObj = JsonNode.Parse(payloadBytes) as JsonObject;
        }
        catch
        {
            return new ProofError("malformed_jwt", "Header or payload is not base64url-decodable JSON.");
        }
        if (headerObj is null || payloadObj is null)
            return new ProofError("malformed_jwt", "Header and payload must be JSON objects.");

        var header = new JsonWebTokenHeader(headerObj);

        if (!string.Equals(header.Type, ExpectedTyp, StringComparison.Ordinal))
            return new ProofError("invalid_typ", $"typ must be '{ExpectedTyp}', got '{header.Type ?? "<missing>"}'.");

        var alg = header.Algorithm;
        if (alg is null || !AllowedAlgorithms.Contains(alg))
            return new ProofError("invalid_alg", $"alg must be an asymmetric algorithm from the whitelist, got '{alg ?? "<missing>"}'.");

        JsonWebKey? jwk;
        try { jwk = header.VerificationKey; }
        catch (JsonException)
        {
            return new ProofError("invalid_jwk", "Header 'jwk' is not a valid JWK.");
        }
        if (jwk is null)
            return new ProofError("missing_jwk", "Header 'jwk' is required.");
        if (jwk.HasPrivateKey)
            return new ProofError("invalid_jwk", "Header 'jwk' must not contain private key material.");

        var signatureError = await signer.ValidateAsync(parts, header, SingleKey(jwk));
        if (signatureError is not null)
            return new ProofError("signature_invalid", signatureError.ErrorDescription);

        var htm = payloadObj["htm"]?.AsValue().TryGetValue<string>(out var htmValue) == true ? htmValue : null;
        if (!string.Equals(htm, httpMethod, StringComparison.Ordinal))
            return new ProofError("htm_mismatch", $"htm '{htm ?? "<missing>"}' does not match request method '{httpMethod}'.");

        var htu = payloadObj["htu"]?.AsValue().TryGetValue<string>(out var htuValue) == true ? htuValue : null;
        if (htu is null)
            return new ProofError("htu_missing", "htu claim is required.");
        if (!Uri.TryCreate(htu, UriKind.Absolute, out var htuUri))
            return new ProofError("htu_invalid", "htu is not a valid absolute URI.");
        if (!string.Equals(htuUri.Normalize(), requestUri.Normalize(), StringComparison.Ordinal))
            return new ProofError("htu_mismatch", "htu does not match the request URI after canonicalisation.");

        DateTimeOffset iat;
        try
        {
            var iatValue = payloadObj.GetUnixTimeSeconds("iat");
            if (iatValue is null)
                return new ProofError("iat_missing", "iat claim is required.");
            iat = iatValue.Value;
        }
        catch
        {
            return new ProofError("iat_invalid", "iat claim is not a valid Unix-time numeric.");
        }
        var now = timeProvider.GetUtcNow();
        if ((iat - now).Duration() > IatTolerance)
            return new ProofError("iat_out_of_window",
                $"iat is outside the {IatTolerance.TotalSeconds:0}-second tolerance window.");

        if (accessToken is not null)
        {
            var ath = payloadObj["ath"]?.AsValue().TryGetValue<string>(out var athValue) == true ? athValue : null;
            if (ath is null)
                return new ProofError("ath_missing", "ath claim is required when an access token is presented.");
            var expectedAth = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            if (!string.Equals(ath, expectedAth, StringComparison.Ordinal))
                return new ProofError("ath_mismatch", "ath does not match the access-token hash.");
        }

        var jti = payloadObj["jti"]?.AsValue().TryGetValue<string>(out var jtiValue) == true ? jtiValue : null;
        if (string.IsNullOrEmpty(jti))
            return new ProofError("jti_missing", "jti claim is required.");

        var jkt = jwk.ComputeJwkThumbprintBase64Url();
        return new Proof(jwk, jkt, jti, iat);
    }

    private static async IAsyncEnumerable<JsonWebKey> SingleKey(JsonWebKey key)
    {
        yield return key;
        await Task.CompletedTask;
    }
}
