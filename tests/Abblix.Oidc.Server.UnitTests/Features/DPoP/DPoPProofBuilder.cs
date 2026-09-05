// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.UnitTests.Features.DPoP;

/// <summary>
/// Builds a signed DPoP proof JWS for tests, with sensible defaults that produce a valid
/// proof for <c>POST https://auth.example.com/token</c>. Each instance generates a fresh
/// EC P-256 keypair; the public-only JWK is exposed via <see cref="PublicJwk"/> so tests
/// can compute the expected <c>jkt</c>.
/// </summary>
internal sealed class DPoPProofBuilder
{
    private readonly ECDsa _ecdsa;
    private readonly DateTimeOffset _now;

    public EllipticCurveJsonWebKey PublicJwk { get; }

    public string Typ { get; init; } = "dpop+jwt";
    public string Alg { get; init; } = "ES256";
    public bool IncludeJwk { get; init; } = true;
    public bool IncludePrivateInJwk { get; init; } = false;
    public string? Htm { get; init; } = "POST";
    public string? Htu { get; init; } = "https://auth.example.com/token";
    public string? Jti { get; init; } = $"test-jti-{Guid.NewGuid():N}";
    public DateTimeOffset? Iat { get; init; }

    /// <summary>
    /// Written into the payload verbatim in place of <see cref="Iat"/>, for a case about a value the
    /// typed accessor would never produce.
    /// </summary>
    public JsonNode? RawIat { get; init; }
    public string? Ath { get; init; }
    public bool CorruptSignature { get; init; }

    public DPoPProofBuilder(DateTimeOffset now)
    {
        _now = now;
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicParams = _ecdsa.ExportParameters(includePrivateParameters: false);
        PublicJwk = new EllipticCurveJsonWebKey
        {
            Algorithm = SigningAlgorithms.ES256,
            Usage = PublicKeyUsages.Signature,
        }.Apply(publicParams);
    }

    public string Build()
    {
        var header = new JsonObject
        {
            ["typ"] = Typ,
            ["alg"] = Alg,
        };
        if (IncludeJwk)
        {
            JsonWebKey jwkForHeader = IncludePrivateInJwk
                ? new EllipticCurveJsonWebKey { Algorithm = SigningAlgorithms.ES256 }
                    .Apply(_ecdsa.ExportParameters(includePrivateParameters: true))
                : PublicJwk;
            header["jwk"] = JsonSerializer.SerializeToNode(jwkForHeader);
        }

        var payload = new JsonObject();
        if (Htm is not null) payload["htm"] = Htm;
        if (Htu is not null) payload["htu"] = Htu;
        if (Jti is not null) payload["jti"] = Jti;
        payload["iat"] = RawIat ?? (Iat ?? _now).ToUnixTimeSeconds();
        if (Ath is not null) payload["ath"] = Ath;

        var headerB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signingInput = $"{headerB64}.{payloadB64}";

        var signature = _ecdsa.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (CorruptSignature && signature.Length > 0)
        {
            signature[0] ^= 0xFF;
        }
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }
}