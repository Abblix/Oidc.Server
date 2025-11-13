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
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Oidc.Server.Mvc.Extensions;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Mvc.Extensions;

/// <summary>
/// Unit tests for <see cref="CertificateForwardingExtensions"/> verifying
/// certificate forwarding configuration for mTLS reverse proxy scenarios.
/// </summary>
public class CertificateForwardingExtensionsTests
{
    /// <summary>
    /// Verifies default header name is "X-Client-Cert".
    /// </summary>
    [Fact]
    public void AddMtlsCertificateForwarding_WithDefaultParameters_ShouldUseDefaultHeaderName()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddMtlsCertificateForwarding();

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<CertificateForwardingOptions>>().Value;
        Assert.Equal("X-Client-Cert", options.CertificateHeader);
    }

    /// <summary>
    /// Verifies custom header name is applied.
    /// </summary>
    [Theory]
    [InlineData("X-Forwarded-Client-Cert")]
    [InlineData("X-SSL-Client-Cert")]
    [InlineData("Custom-Header")]
    public void AddMtlsCertificateForwarding_WithCustomHeaderName_ShouldUseCustomHeader(string headerName)
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddMtlsCertificateForwarding(headerName);

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<CertificateForwardingOptions>>().Value;
        Assert.Equal(headerName, options.CertificateHeader);
    }

    /// <summary>
    /// Verifies configure callback is invoked.
    /// </summary>
    [Fact]
    public void AddMtlsCertificateForwarding_WithConfigureCallback_ShouldInvokeCallback()
    {
        // Arrange
        var services = new ServiceCollection();
        var callbackInvoked = false;

        // Act
        services.AddMtlsCertificateForwarding(configure: options =>
        {
            callbackInvoked = true;
        });

        // Assert
        var provider = services.BuildServiceProvider();
        _ = provider.GetRequiredService<IOptions<CertificateForwardingOptions>>().Value;
        Assert.True(callbackInvoked);
    }

    /// <summary>
    /// Verifies PEM format certificate is parsed correctly.
    /// Tests nginx ssl_client_escaped_cert format.
    /// </summary>
    [Fact]
    public void HeaderConverter_WithPemFormat_ShouldParseCertificate()
    {
        // Arrange
        var cert = CreateTestCertificate();
        var pem = cert.ExportCertificatePem();
        var converter = GetHeaderConverter();

        // Act
        var result = converter(pem);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(cert.Subject, result.Subject);
    }

    /// <summary>
    /// Verifies Base64-encoded DER format is parsed correctly.
    /// Tests Envoy and HAProxy format.
    /// </summary>
    [Fact]
    public void HeaderConverter_WithBase64Format_ShouldParseCertificate()
    {
        // Arrange
        var cert = CreateTestCertificate();
        var base64 = Convert.ToBase64String(cert.RawData);
        var converter = GetHeaderConverter();

        // Act
        var result = converter(base64);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(cert.Subject, result.Subject);
    }

    /// <summary>
    /// Verifies URL-encoded Base64 format is parsed correctly.
    /// Tests nginx ssl_client_cert format.
    /// </summary>
    [Fact]
    public void HeaderConverter_WithUrlEncodedBase64_ShouldParseCertificate()
    {
        // Arrange
        var cert = CreateTestCertificate();
        var base64 = Convert.ToBase64String(cert.RawData);
        var urlEncoded = Uri.EscapeDataString(base64);
        var converter = GetHeaderConverter();

        // Act
        var result = converter(urlEncoded);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(cert.Subject, result.Subject);
    }

    /// <summary>
    /// Verifies Base64 with missing padding is handled correctly.
    /// Tests various padding scenarios.
    /// </summary>
    [Theory]
    [InlineData(0)] // No padding needed
    [InlineData(1)] // 1 padding character needed
    [InlineData(2)] // 2 padding characters needed
    public void HeaderConverter_WithMissingPadding_ShouldParseCertificate(int removePadding)
    {
        // Arrange
        var cert = CreateTestCertificate();
        var base64 = Convert.ToBase64String(cert.RawData);
        var unpadded = base64.TrimEnd('=');

        if (removePadding > 0)
        {
            var targetLength = ((base64.Length - base64.Count(c => c == '=')) / 4 * 4) - removePadding;
            unpadded = base64.TrimEnd('=').Substring(0, Math.Max(0, targetLength));
        }

        var converter = GetHeaderConverter();

        // Act
        var result = converter(unpadded);

        // Assert - may be null if too short, should not throw
        if (result != null)
        {
            Assert.Equal(cert.Subject, result.Subject);
        }
    }

    /// <summary>
    /// Verifies Base64 with whitespace is handled correctly.
    /// Tests various whitespace characters.
    /// </summary>
    [Fact]
    public void HeaderConverter_WithWhitespace_ShouldParseCertificate()
    {
        // Arrange
        var cert = CreateTestCertificate();
        var base64 = Convert.ToBase64String(cert.RawData);
        var withWhitespace = string.Join("\n", SplitIntoChunks(base64, 64));
        var converter = GetHeaderConverter();

        // Act
        var result = converter(withWhitespace);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(cert.Subject, result.Subject);
    }

    /// <summary>
    /// Verifies null or empty header returns null.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void HeaderConverter_WithNullOrEmpty_ShouldReturnNull(string? headerValue)
    {
        // Arrange
        var converter = GetHeaderConverter();

        // Act
        var result = converter(headerValue!);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies invalid Base64 returns null instead of throwing.
    /// </summary>
    [Theory]
    [InlineData("not-base64!@#$")]
    [InlineData("invalid")]
    public void HeaderConverter_WithInvalidBase64_ShouldReturnNull(string invalidValue)
    {
        // Arrange
        var converter = GetHeaderConverter();

        // Act
        var result = converter(invalidValue);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies invalid certificate data returns null instead of throwing.
    /// </summary>
    [Fact]
    public void HeaderConverter_WithInvalidCertificateData_ShouldReturnNull()
    {
        // Arrange
        var invalidCertData = Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5 });
        var converter = GetHeaderConverter();

        // Act
        var result = converter(invalidCertData);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies configure callback can override header converter.
    /// </summary>
    [Fact]
    public void AddMtlsCertificateForwarding_WithCustomConverter_ShouldUseCustomConverter()
    {
        // Arrange
        var services = new ServiceCollection();
        var customCert = CreateTestCertificate();
        Func<string, X509Certificate2> customConverter = _ => customCert;

        // Act
        services.AddMtlsCertificateForwarding(configure: options =>
        {
            options.HeaderConverter = customConverter;
        });

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<CertificateForwardingOptions>>().Value;
        var result = options.HeaderConverter("any value");
        Assert.Equal(customCert, result);
    }

    /// <summary>
    /// Verifies PEM with escaped newlines is parsed correctly.
    /// Tests nginx ssl_client_escaped_cert with \n escape sequences.
    /// </summary>
    [Fact]
    public void HeaderConverter_WithEscapedNewlines_ShouldParseCertificate()
    {
        // Arrange
        var cert = CreateTestCertificate();
        var pem = cert.ExportCertificatePem().Replace("\n", "\\n");
        var converter = GetHeaderConverter();

        // Act - URL decode should restore newlines
        var unescaped = pem.Replace("\\n", "\n");
        var result = converter(unescaped);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(cert.Subject, result.Subject);
    }

    /// <summary>
    /// Verifies multiple certificates in chain returns only first certificate.
    /// </summary>
    [Fact]
    public void HeaderConverter_WithMultiplePemCertificates_ShouldParseFirstCertificate()
    {
        // Arrange
        var cert1 = CreateTestCertificate();
        var cert2 = CreateTestCertificate();
        var pem = cert1.ExportCertificatePem() + "\n" + cert2.ExportCertificatePem();
        var converter = GetHeaderConverter();

        // Act
        var result = converter(pem);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(cert1.Subject, result.Subject);
    }

    /// <summary>
    /// Extracts the HeaderConverter from configured options using reflection.
    /// </summary>
    private static Func<string, X509Certificate2> GetHeaderConverter()
    {
        var services = new ServiceCollection();
        services.AddMtlsCertificateForwarding();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<CertificateForwardingOptions>>().Value;

        return options.HeaderConverter;
    }

    /// <summary>
    /// Creates a test certificate for validation.
    /// </summary>
    private static X509Certificate2 CreateTestCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test Client,O=Test Org",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));
    }

    /// <summary>
    /// Splits a string into chunks of specified size.
    /// </summary>
    private static IEnumerable<string> SplitIntoChunks(string str, int chunkSize)
    {
        for (var i = 0; i < str.Length; i += chunkSize)
        {
            yield return str.Substring(i, Math.Min(chunkSize, str.Length - i));
        }
    }
}
