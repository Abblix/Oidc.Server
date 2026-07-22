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
using Abblix.Oidc.Server.Mvc.Extensions;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Extensions;

/// <summary>
/// Tests the header converter registered by
/// <see cref="CertificateForwardingExtensions.AddMtlsCertificateForwarding"/>.
/// </summary>
/// <remarks>
/// This converter turns a header written by a reverse proxy into the client certificate that mTLS client
/// authentication then treats as the client's identity. Two failures matter and neither is cosmetic: producing
/// a certificate other than the one the header carried would authenticate the wrong client, and failing to
/// parse a shape a real proxy emits would lock a correctly configured client out.
///
/// The converter is exercised through the options the extension registers rather than as a private function,
/// because what the middleware calls is what is registered, and testing a copy proves nothing about it.
/// </remarks>
public class CertificateForwardingExtensionsTests
{
    /// <summary>
    /// Fixed validity window rather than one measured from the clock: the certificate here is a carrier for
    /// bytes, and nothing under test reads its dates, so a moving window would only add a way to fail on a
    /// slow machine.
    /// </summary>
    private static readonly DateTimeOffset NotBefore = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=client.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(NotBefore, NotBefore.AddYears(10));
    }

    private static Func<string, X509Certificate2?> ConverterOf(
        string headerName = "X-Client-Cert", Action<CertificateForwardingOptions>? configure = null)
        => OptionsOf(headerName, configure).HeaderConverter;

    private static CertificateForwardingOptions OptionsOf(
        string headerName = "X-Client-Cert", Action<CertificateForwardingOptions>? configure = null)
    {
        var provider = new ServiceCollection()
            .AddMtlsCertificateForwarding(headerName, configure)
            .BuildServiceProvider();

        return provider.GetRequiredService<IOptions<CertificateForwardingOptions>>().Value;
    }

    [Fact]
    public void The_configured_header_name_is_the_one_the_middleware_reads()
    {
        Assert.Equal("X-Forwarded-Client-Cert", OptionsOf("X-Forwarded-Client-Cert").CertificateHeader);
    }

    [Fact]
    public void A_pem_header_yields_the_very_certificate_it_carried()
    {
        // nginx with ssl_client_escaped_cert emits PEM. Comparing thumbprints rather than merely asserting
        // that something parsed is the point: a converter returning a different certificate authenticates a
        // different client.
        using var certificate = CreateCertificate();

        var parsed = ConverterOf()(certificate.ExportCertificatePem());

        Assert.NotNull(parsed);
        Assert.Equal(certificate.Thumbprint, parsed.Thumbprint);
    }

    [Fact]
    public void A_raw_base64_header_yields_the_very_certificate_it_carried()
    {
        // Envoy and HAProxy send base64-encoded DER.
        using var certificate = CreateCertificate();

        var parsed = ConverterOf()(Convert.ToBase64String(certificate.RawData));

        Assert.NotNull(parsed);
        Assert.Equal(certificate.Thumbprint, parsed.Thumbprint);
    }

    [Fact]
    public void A_url_encoded_header_yields_the_very_certificate_it_carried()
    {
        // nginx with ssl_client_cert percent-encodes what it forwards.
        using var certificate = CreateCertificate();

        var parsed = ConverterOf()(Uri.EscapeDataString(Convert.ToBase64String(certificate.RawData)));

        Assert.NotNull(parsed);
        Assert.Equal(certificate.Thumbprint, parsed.Thumbprint);
    }

    [Fact]
    public void Base64_stripped_of_its_padding_is_still_accepted()
    {
        // Padding is routinely dropped in transit. Rejecting an unpadded value would lock out a correctly
        // configured client, and the failure would read as a certificate problem rather than an encoding one.
        using var certificate = CreateCertificate();

        var parsed = ConverterOf()(Convert.ToBase64String(certificate.RawData).TrimEnd('='));

        Assert.NotNull(parsed);
        Assert.Equal(certificate.Thumbprint, parsed.Thumbprint);
    }

    [Fact]
    public void Base64_broken_across_lines_is_still_accepted()
    {
        // Proxies and configuration files wrap long values; the whitespace is not part of the encoding.
        using var certificate = CreateCertificate();
        var wrapped = string.Join("\n", Chunk(Convert.ToBase64String(certificate.RawData), 64));

        var parsed = ConverterOf()(wrapped);

        Assert.NotNull(parsed);
        Assert.Equal(certificate.Thumbprint, parsed.Thumbprint);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-certificate")]
    [InlineData("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----")]
    [InlineData("AAAA")]
    public void A_header_that_is_not_a_certificate_produces_nothing(string headerValue)
    {
        // The header arrives from outside. A converter that produced anything at all out of junk would hand
        // the authentication layer an identity nobody presented, so the only safe answer is none.
        Assert.Null(ConverterOf()(headerValue));
    }

    [Fact]
    public void The_host_callback_runs_after_the_defaults_so_it_can_override_them()
    {
        // If it ran first, a host would appear to configure the converter while the defaults silently won.
        var options = OptionsOf(configure: settings => settings.CertificateHeader = "X-Overridden");

        Assert.Equal("X-Overridden", options.CertificateHeader);
        Assert.NotNull(options.HeaderConverter);
    }

    private static IEnumerable<string> Chunk(string value, int size)
    {
        for (var offset = 0; offset < value.Length; offset += size)
            yield return value.Substring(offset, Math.Min(size, value.Length - offset));
    }
}
