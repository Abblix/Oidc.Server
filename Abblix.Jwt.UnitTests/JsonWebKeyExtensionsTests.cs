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

using System;
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
}
