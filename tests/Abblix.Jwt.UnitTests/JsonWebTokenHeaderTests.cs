// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for the typed accessors on <see cref="JsonWebTokenHeader"/> covering the optional
/// JOSE header parameters defined in RFC 7515 section 4.1.2 - section 4.1.8: <c>jku</c>, <c>jwk</c>,
/// <c>x5u</c>, <c>x5c</c>, <c>x5t</c>, <c>x5t#S256</c>.
///
/// The accessors are a thin typed surface over <see cref="JsonWebTokenHeader.Json"/>; they do
/// NOT consume the values for key resolution. Tests cover three concerns per accessor:
/// reading from a producer-shaped header, writing then reading round-trip, and the
/// missing/null erasure semantics.
/// </summary>
public class JsonWebTokenHeaderTests
{
    private static JsonWebTokenHeader EmptyHeader() => new(new JsonObject());

    // ─────────────────────────────────────────────────────────────────────────────
    // jku - RFC 7515 section 4.1.2 (URL of a JWK Set whose keys verify the JWS)
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void JwkSetUrl_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.Null(header.JwkSetUrl);
    }

    [Fact]
    public void JwkSetUrl_PresentAsString_ReturnsParsedUri()
    {
        var json = new JsonObject { [JwtClaimTypes.JwkSetUrl] = "https://issuer.example.com/jwks.json" };
        var header = new JsonWebTokenHeader(json);

        Assert.Equal(new Uri("https://issuer.example.com/jwks.json"), header.JwkSetUrl);
    }

    [Fact]
    public void JwkSetUrl_SetThenGet_RoundTrips()
    {
        var header = EmptyHeader();

        header.JwkSetUrl = new Uri("https://issuer.example.com/jwks.json");

        Assert.Equal(new Uri("https://issuer.example.com/jwks.json"), header.JwkSetUrl);
        Assert.Equal("https://issuer.example.com/jwks.json", (string?)header.Json[JwtClaimTypes.JwkSetUrl]);
    }

    [Fact]
    public void JwkSetUrl_SetNull_RemovesProperty()
    {
        var header = EmptyHeader();
        header.JwkSetUrl = new Uri("https://issuer.example.com/jwks.json");

        header.JwkSetUrl = null;

        Assert.False(header.Json.ContainsKey(JwtClaimTypes.JwkSetUrl));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // jwk - RFC 7515 section 4.1.3 (public key embedded directly as a JWK)
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void VerificationKey_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.True(header.TryReadVerificationKey(out var key));
        Assert.Null(key);
    }

    [Fact]
    public void VerificationKey_PresentAsObject_ReturnsParsedKey()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature).Sanitize(includePrivateKeys: false);
        var keyJson = JsonNode.Parse(JsonSerializer.Serialize(key))!.AsObject();
        var json = new JsonObject { [JwtClaimTypes.JsonWebKeyHeader] = keyJson };
        var header = new JsonWebTokenHeader(json);

        Assert.True(header.TryReadVerificationKey(out var parsed));

        Assert.NotNull(parsed);
        Assert.Equal(key.KeyType, parsed.KeyType);
        Assert.Equal(key.KeyId, parsed.KeyId);
    }

    /// <summary>A 'jwk' that is an object but no valid key is malformed, not absent.</summary>
    [Fact]
    public void VerificationKey_PresentAsAnInvalidKey_IsMalformed()
    {
        var json = new JsonObject { [JwtClaimTypes.JsonWebKeyHeader] = new JsonObject { ["kty"] = "unknown" } };
        var header = new JsonWebTokenHeader(json);

        Assert.False(header.TryReadVerificationKey(out _));
    }

    /// <summary>A 'jwk' that is not a JSON object is malformed, as a 'crit' that is not an array is.</summary>
    [Fact]
    public void VerificationKey_PresentAsAString_IsMalformed()
    {
        var json = new JsonObject { [JwtClaimTypes.JsonWebKeyHeader] = "not a key" };
        var header = new JsonWebTokenHeader(json);

        Assert.False(header.TryReadVerificationKey(out _));
    }

    /// <summary>
    /// An 'epk' carries only the members the ephemeral key has (kty, crv, x, y), the wire form conformant JOSE peers
    /// emit and expect, with no absent member written as a JSON null.
    /// </summary>
    [Fact]
    public void EphemeralPublicKey_IsWrittenWithItsOwnMembersOnly()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var key = new EllipticCurveJsonWebKey().Apply(ecdh.ExportParameters(false)) with { Algorithm = null };
        var header = EmptyHeader();

        header.SetEphemeralPublicKey(key);

        var written = header.Json[JwtClaimTypes.EphemeralPublicKey]!.AsObject().Select(member => member.Key);
        Assert.Equal(["crv", "kty", "x", "y"], written.Order());
    }

    /// <summary>An 'epk' that is an object but no valid key is malformed, not absent.</summary>
    [Fact]
    public void EphemeralPublicKey_PresentAsAnInvalidKey_IsMalformed()
    {
        var json = new JsonObject { [JwtClaimTypes.EphemeralPublicKey] = new JsonObject { ["kty"] = "unknown" } };
        var header = new JsonWebTokenHeader(json);

        Assert.False(header.TryReadEphemeralPublicKey(out _));
    }

    [Fact]
    public void VerificationKey_SetThenGet_RoundTrips()
    {
        var header = EmptyHeader();
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature).Sanitize(includePrivateKeys: false);

        header.SetVerificationKey(key);
        Assert.True(header.TryReadVerificationKey(out var parsed));

        Assert.NotNull(parsed);
        Assert.Equal(key.KeyType, parsed.KeyType);
        Assert.Equal(key.KeyId, parsed.KeyId);
    }

    [Fact]
    public void VerificationKey_SetNull_RemovesProperty()
    {
        var header = EmptyHeader();
        header.SetVerificationKey(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature).Sanitize(includePrivateKeys: false));

        header.SetVerificationKey(null);

        Assert.False(header.Json.ContainsKey(JwtClaimTypes.JsonWebKeyHeader));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // x5u - RFC 7515 section 4.1.5 (URL of an X.509 certificate or chain)
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void CertificatesUrl_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.Null(header.CertificatesUrl);
    }

    [Fact]
    public void CertificatesUrl_PresentAsString_ReturnsParsedUri()
    {
        var json = new JsonObject { [JwtClaimTypes.X509Url] = "https://issuer.example.com/cert.pem" };
        var header = new JsonWebTokenHeader(json);

        Assert.Equal(new Uri("https://issuer.example.com/cert.pem"), header.CertificatesUrl);
    }

    [Fact]
    public void CertificatesUrl_SetThenGet_RoundTrips()
    {
        var header = EmptyHeader();

        header.CertificatesUrl = new Uri("https://issuer.example.com/cert.pem");

        Assert.Equal(new Uri("https://issuer.example.com/cert.pem"), header.CertificatesUrl);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // x5c - RFC 7515 section 4.1.6 (X.509 certificate chain as a JSON array of base64-DER)
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Certificates_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.True(header.TryReadCertificates(out var chain));
        Assert.Null(chain);
    }

    [Fact]
    public void Certificates_PresentAsArray_ReturnsAllEntries()
    {
        var leaf = "MIIDleafBASE64==";
        var intermediate = "MIIDintermediateBASE64==";
        var json = new JsonObject
        {
            [JwtClaimTypes.X509CertificateChain] = new JsonArray(leaf, intermediate),
        };
        var header = new JsonWebTokenHeader(json);

        Assert.True(header.TryReadCertificates(out var chain));

        Assert.NotNull(chain);
        Assert.Equal([leaf, intermediate], chain);
    }

    [Fact]
    public void Certificates_SetThenGet_RoundTrips()
    {
        var header = EmptyHeader();
        var chain = new[] { "MIIDleaf==", "MIIDintermediate==" };

        header.SetCertificates(chain);

        Assert.True(header.TryReadCertificates(out var read));
        Assert.Equal(chain, read);
    }

    [Fact]
    public void Certificates_PresentAsNonArray_IsMalformed()
    {
        var json = new JsonObject { [JwtClaimTypes.X509CertificateChain] = "MIIDleaf==" };
        var header = new JsonWebTokenHeader(json);

        Assert.False(header.TryReadCertificates(out _));
    }

    [Fact]
    public void Certificates_SetNull_RemovesProperty()
    {
        var header = EmptyHeader();
        header.SetCertificates(["MIIDleaf=="]);

        header.SetCertificates(null);

        Assert.False(header.Json.ContainsKey(JwtClaimTypes.X509CertificateChain));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // x5t - RFC 7515 section 4.1.7 (base64url SHA-1 thumbprint, deprecated per section 10.11)
    // x5t#S256 - RFC 7515 section 4.1.8 (base64url SHA-256 thumbprint)
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void CertificateSha1Thumbprint_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.Null(header.CertificateSha1Thumbprint);
    }

    [Fact]
    public void CertificateSha1Thumbprint_RoundTrips()
    {
        var header = EmptyHeader();
        const string thumbprint = "dGhpcy1pcy1hLXNoYTEtdGh1bWJwcmludA";

        header.CertificateSha1Thumbprint = thumbprint;

        Assert.Equal(thumbprint, header.CertificateSha1Thumbprint);
        Assert.Equal(thumbprint, (string?)header.Json[JwtClaimTypes.X509Sha1Thumbprint]);
    }

    [Fact]
    public void CertificateSha256Thumbprint_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.Null(header.CertificateSha256Thumbprint);
    }

    [Fact]
    public void CertificateSha256Thumbprint_RoundTrips()
    {
        var header = EmptyHeader();
        const string thumbprint = "dGhpcy1pcy1hLXNoYTI1Ni10aHVtYnByaW50LWZyb20tdGhlLWNlcnQ";

        header.CertificateSha256Thumbprint = thumbprint;

        Assert.Equal(thumbprint, header.CertificateSha256Thumbprint);
        Assert.Equal(thumbprint, (string?)header.Json[JwtClaimTypes.X509Sha256Thumbprint]);
    }

    /// <summary>
    /// Confirms the JSON literal stays <c>x5t#S256</c> even though the C# member name strips
    /// the <c>#</c> - RFC compliance lives in the constant, not the member name.
    /// </summary>
    [Fact]
    public void CertificateSha256Thumbprint_StoresUnderSpecLiteral()
    {
        var header = EmptyHeader();

        header.CertificateSha256Thumbprint = "thumb";

        Assert.True(header.Json.ContainsKey(JwtClaimTypes.X509Sha256Thumbprint));
    }
}
