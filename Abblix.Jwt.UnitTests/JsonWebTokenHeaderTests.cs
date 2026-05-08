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

using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for the typed accessors on <see cref="JsonWebTokenHeader"/> covering the optional
/// JOSE header parameters defined in RFC 7515 §4.1.2 — §4.1.8: <c>jku</c>, <c>jwk</c>,
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
    // jku — RFC 7515 §4.1.2 (URL of a JWK Set whose keys verify the JWS)
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
    // jwk — RFC 7515 §4.1.3 (public key embedded directly as a JWK)
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void VerificationKey_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.Null(header.VerificationKey);
    }

    [Fact]
    public void VerificationKey_PresentAsObject_ReturnsParsedKey()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature).Sanitize(includePrivateKeys: false);
        var keyJson = JsonNode.Parse(JsonSerializer.Serialize(key))!.AsObject();
        var json = new JsonObject { [JwtClaimTypes.JsonWebKeyHeader] = keyJson };
        var header = new JsonWebTokenHeader(json);

        var parsed = header.VerificationKey;

        Assert.NotNull(parsed);
        Assert.Equal(key.KeyType, parsed!.KeyType);
        Assert.Equal(key.KeyId, parsed.KeyId);
    }

    [Fact]
    public void VerificationKey_SetThenGet_RoundTrips()
    {
        var header = EmptyHeader();
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature).Sanitize(includePrivateKeys: false);

        header.VerificationKey = key;
        var parsed = header.VerificationKey;

        Assert.NotNull(parsed);
        Assert.Equal(key.KeyType, parsed!.KeyType);
        Assert.Equal(key.KeyId, parsed.KeyId);
    }

    [Fact]
    public void VerificationKey_SetNull_RemovesProperty()
    {
        var header = EmptyHeader();
        header.VerificationKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature).Sanitize(includePrivateKeys: false);

        header.VerificationKey = null;

        Assert.False(header.Json.ContainsKey(JwtClaimTypes.JsonWebKeyHeader));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // x5u — RFC 7515 §4.1.5 (URL of an X.509 certificate or chain)
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
    // x5c — RFC 7515 §4.1.6 (X.509 certificate chain as a JSON array of base64-DER)
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Certificates_Missing_ReturnsNull()
    {
        var header = EmptyHeader();

        Assert.Null(header.Certificates);
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

        var chain = header.Certificates;

        Assert.NotNull(chain);
        Assert.Equal([leaf, intermediate], chain);
    }

    [Fact]
    public void Certificates_SetThenGet_RoundTrips()
    {
        var header = EmptyHeader();
        var chain = new[] { "MIIDleaf==", "MIIDintermediate==" };

        header.Certificates = chain;

        Assert.Equal(chain, header.Certificates);
    }

    [Fact]
    public void Certificates_PresentAsNonArray_Throws()
    {
        var json = new JsonObject { [JwtClaimTypes.X509CertificateChain] = "MIIDleaf==" };
        var header = new JsonWebTokenHeader(json);

        Assert.Throws<JsonException>(() => header.Certificates);
    }

    [Fact]
    public void Certificates_SetNull_RemovesProperty()
    {
        var header = EmptyHeader();
        header.Certificates = ["MIIDleaf=="];

        header.Certificates = null;

        Assert.False(header.Json.ContainsKey(JwtClaimTypes.X509CertificateChain));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // x5t — RFC 7515 §4.1.7 (base64url SHA-1 thumbprint, deprecated per §10.11)
    // x5t#S256 — RFC 7515 §4.1.8 (base64url SHA-256 thumbprint)
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
    /// the <c>#</c> — RFC compliance lives in the constant, not the member name.
    /// </summary>
    [Fact]
    public void CertificateSha256Thumbprint_StoresUnderSpecLiteral()
    {
        var header = EmptyHeader();

        header.CertificateSha256Thumbprint = "thumb";

        Assert.True(header.Json.ContainsKey(JwtClaimTypes.X509Sha256Thumbprint));
    }
}
