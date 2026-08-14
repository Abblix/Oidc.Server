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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Verifies how <see cref="JsonWebKeyExtensions.ToJsonWebKey"/> derives the JWK <c>use</c> from a certificate's
/// Key Usage extension: one value for a single-purpose certificate, and no <c>use</c> (never a multi-valued
/// string such as "sig enc") for one that permits both signing and encryption, per RFC 7517 &#167;4.2.
/// </summary>
public class JsonWebKeyExtensionsTests
{
    [Theory]
    [InlineData(X509KeyUsageFlags.DigitalSignature, PublicKeyUsages.Signature)]
    [InlineData(X509KeyUsageFlags.KeyEncipherment, PublicKeyUsages.Encryption)]
    [InlineData(X509KeyUsageFlags.DataEncipherment, PublicKeyUsages.Encryption)]
    [InlineData(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, null)]
    [InlineData(
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
        null)]
    [InlineData(X509KeyUsageFlags.None, PublicKeyUsages.Signature)]
    public void ToJsonWebKey_DerivesUseFromKeyUsageExtension(X509KeyUsageFlags flags, string? expectedUse)
    {
        using var certificate = CreateRsaCertificate(flags);

        var jwk = certificate.ToJsonWebKey();

        // A certificate that permits both roles yields no use (unrestricted), not the invalid "sig enc" string.
        // A single encipherment flag is enough to mark encryption.
        Assert.Equal(expectedUse, jwk.Usage);
    }

    [Fact]
    public void ToJsonWebKey_DefaultsToSignatureUse_WhenCertificateHasNoKeyUsageExtension()
    {
        using var certificate = CreateRsaCertificate(keyUsage: null);

        var jwk = certificate.ToJsonWebKey();

        Assert.Equal(PublicKeyUsages.Signature, jwk.Usage);
    }

    private static X509Certificate2 CreateRsaCertificate(X509KeyUsageFlags? keyUsage)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Abblix Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        if (keyUsage is { } flags)
            request.CertificateExtensions.Add(new X509KeyUsageExtension(flags, critical: false));

        // Fixed validity window: ToJsonWebKey does not read it, so this introduces no clock dependency.
        var notBefore = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero);
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    /// <summary>
    /// A key declaring no algorithm is answerable, not unknown: RFC 7518 section 3.1 binds each signature
    /// algorithm to a key type and section 3.4 binds each ECDSA one to a single curve, so the material settles
    /// what the declaration left open. This is the ordinary case for a certificate-imported key, which never
    /// carries an <c>alg</c>.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, true)]
    [InlineData(SigningAlgorithms.PS512, true)]
    [InlineData(SigningAlgorithms.ES256, false)]   // needs an EC key on P-256
    [InlineData(SigningAlgorithms.HS256, false)]   // needs a symmetric key
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, true)]
    [InlineData(EncryptionAlgorithms.KeyManagement.EcdhEs, false)]
    [InlineData(SigningAlgorithms.None, false)]
    [InlineData("made-up", false)]
    public void RsaKey_SupportsExactlyTheAlgorithmsItsMaterialCanPerform(string algorithm, bool expected)
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

        Assert.Equal(expected, key.SupportsAlgorithm(algorithm));
    }

    /// <summary>
    /// ECDSA is the case where the key type is not enough: the algorithm names the curve, so a P-256 key
    /// performs ES256 and neither of the other two. Getting this wrong would surface as a signature failure
    /// rather than a selection failure, one layer away from the cause.
    /// </summary>
    [Theory]
    [InlineData(EllipticCurveTypes.P256, SigningAlgorithms.ES256, true)]
    [InlineData(EllipticCurveTypes.P256, SigningAlgorithms.ES384, false)]
    [InlineData(EllipticCurveTypes.P384, SigningAlgorithms.ES384, true)]
    [InlineData(EllipticCurveTypes.P521, SigningAlgorithms.ES512, true)]
    [InlineData(EllipticCurveTypes.P256, SigningAlgorithms.RS256, false)]
    [InlineData(EllipticCurveTypes.P256, EncryptionAlgorithms.KeyManagement.EcdhEs, true)]
    public void EllipticCurveKey_IsJudgedByItsCurve(string curve, string algorithm, bool expected)
    {
        var key = JsonWebKeyFactory.CreateEllipticCurve(curve, SigningAlgorithms.ES256);

        Assert.Equal(expected, key.SupportsAlgorithm(algorithm));
    }
}
