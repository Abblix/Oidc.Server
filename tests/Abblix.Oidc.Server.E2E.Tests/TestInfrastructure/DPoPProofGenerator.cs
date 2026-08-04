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
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Mints signed DPoP proof JWS values for E2E flows. One generator instance owns one
/// ECDSA P-256 keypair (the proof-of-possession key the access token will be bound to);
/// it produces a fresh proof per call, each carrying its own <c>jti</c> and current-time
/// <c>iat</c> so the replay cache lets it through. The same instance is reused across
/// PAR + /token + /userinfo in a single flow so every step proves possession of the
/// same key - that's the whole RFC 9449 invariant.
/// </summary>
/// <remarks>
/// Mirrors the unit-test <c>DPoPProofBuilder</c> in shape (the validator's view of a
/// proof is identical regardless of who built it), but lives in the E2E test assembly
/// so scenario files can mint proofs directly without crossing assembly boundaries.
/// The unit-side builder offers fine-grained mutation knobs (CorruptSignature,
/// IncludePrivateInJwk, ...) for negative validation tests; this generator stays on the
/// success path because E2E scenarios drive negatives via "wrong key" / "no header" /
/// "wrong URI" - different keypairs and method/URI inputs, not crafted bad proofs.
/// </remarks>
public sealed class DPoPProofGenerator : IDisposable
{
    private readonly ECDsa _ecdsa;
    private readonly TimeProvider _timeProvider;

    public DPoPProofGenerator(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicParams = _ecdsa.ExportParameters(includePrivateParameters: false);
        PublicJwk = new EllipticCurveJsonWebKey
        {
            Algorithm = SigningAlgorithms.ES256,
            Usage = PublicKeyUsages.Signature,
        }.Apply(publicParams);
    }

    /// <summary>Public half of the proof-of-possession key - what the AS sees in the
    /// proof's <c>jwk</c> header and what the issued access token's <c>cnf.jkt</c>
    /// binds to.</summary>
    public EllipticCurveJsonWebKey PublicJwk { get; }

    /// <summary>RFC 7638 JWK thumbprint of <see cref="PublicJwk"/>, base64url-encoded -
    /// the value the AS commits to as <c>dpop_jkt</c> on PAR and emits as <c>cnf.jkt</c>
    /// on the access token. Tests assert against this verbatim.</summary>
    public string Thumbprint => PublicJwk.ComputeJwkThumbprintBase64Url();

    /// <summary>
    /// Builds a DPoP proof for the given request, signed with this generator's keypair.
    /// Each call mints a fresh <c>jti</c> and uses the current wall-clock <c>iat</c>;
    /// presenting the same returned string twice trips the AS replay cache on the second
    /// attempt (the canonical E2E replay scenario).
    /// </summary>
    /// <param name="httpMethod">HTTP method byte-exact (RFC 9449 §4.2 <c>htm</c>).
    /// Uppercase per IETF convention.</param>
    /// <param name="requestUri">Absolute URI of the request after RFC 3986 §6.2
    /// canonicalisation. Pass exactly what the client will send on the wire; the
    /// validator canonicalises both sides before comparing.</param>
    /// <param name="accessToken">When the proof accompanies an access token at a
    /// protected resource, the proof MUST carry <c>ath = base64url(sha256(token))</c>
    /// per RFC 9449 §4.2. Pass the raw access token here and the generator embeds the
    /// hash. Leave null at the /token endpoint and elsewhere proof-only.</param>
    /// <param name="nonce">RFC 9449 §8 server-supplied freshness nonce. Pass the value
    /// from the previous response's <c>DPoP-Nonce</c> header when the AS challenged for
    /// one; leave null for nonce-disabled deployments (the E2E default).</param>
    public string BuildProof(
        string httpMethod,
        Uri requestUri,
        string? accessToken = null,
        string? nonce = null)
    {
        var header = new JsonObject
        {
            ["typ"] = JsonWebTokenTypes.DPoPProof,
            ["alg"] = SigningAlgorithms.ES256,
            [JwtClaimTypes.JsonWebKeyHeader] = JsonSerializer.SerializeToNode(PublicJwk),
        };

        var payload = new JsonObject
        {
            [JwtClaimTypes.DPoPHttpMethod] = httpMethod,
            [JwtClaimTypes.DPoPHttpUri] = requestUri.AbsoluteUri,
            [JwtClaimTypes.JwtId] = Guid.NewGuid().ToString("N"),
            [JwtClaimTypes.IssuedAt] = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
        };

        if (accessToken is not null)
        {
            payload[JwtClaimTypes.DPoPAccessTokenHash] =
                Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        }

        if (nonce is not null)
            payload[IanaClaimTypes.Nonce] = nonce;

        var headerB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signingInput = $"{headerB64}.{payloadB64}";

        var signature = _ecdsa.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    public void Dispose() => _ecdsa.Dispose();
}
