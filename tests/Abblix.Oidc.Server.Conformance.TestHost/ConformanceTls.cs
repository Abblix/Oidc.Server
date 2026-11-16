// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The host's two listeners: the issuer's, and the mutual-TLS endpoint aliases', each with its own certificate.
/// </summary>
public static class ConformanceTls
{
    /// <summary>Listens on the issuer's port and on the mutual-TLS aliases' port.</summary>
    /// <param name="webHost">The host's web host builder.</param>
    /// <param name="issuer">The issuer, whose host name the first certificate names.</param>
    /// <param name="mtlsBase">The base of the mutual-TLS endpoint aliases, whose host name the second names.</param>
    public static void ListenForSuite(this IWebHostBuilder webHost, Uri issuer, Uri mtlsBase)
    {
        // The suite does not check this server's certificate, so a fresh self-signed one for each name will do
        webHost.ConfigureKestrel(kestrel =>
        {
            kestrel.ListenAnyIP(issuer.Port, listen => listen.UseHttps(FapiTls(new HttpsConnectionAdapterOptions
            {
                ServerCertificate = CreateCertificate(issuer.Host),
            })));

            // The mutual-TLS endpoint aliases (RFC 8705 section 5) take any client certificate: the server matches it
            // against the client's registered keys, or binds the token to it
            kestrel.ListenAnyIP(mtlsBase.Port, listen => listen.UseHttps(FapiTls(new HttpsConnectionAdapterOptions
            {
                ServerCertificate = CreateCertificate(mtlsBase.Host),
                ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                ClientCertificateValidation = (_, _, _) => true,
            })));
        });
    }

    // FAPI 2.0 Security Profile section 5.2.2 and FAPI 1.0 Part 2 section 8.5 hold TLS 1.2 to the cipher suites BCP 195
    // recommends, which the FAPI plans check by offering others. The platform takes a cipher suite policy on Linux
    // only, where the host runs in the suite's network; elsewhere its defaults stay
    private static HttpsConnectionAdapterOptions FapiTls(HttpsConnectionAdapterOptions options)
    {
        if (!OperatingSystem.IsLinux())
            return options;

        var policy = new CipherSuitesPolicy(
        [
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        ]);
        options.OnAuthenticate = (_, ssl) => ssl.CipherSuitesPolicy = policy;
        return options;
    }

    private static X509Certificate2 CreateCertificate(string hostName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={hostName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(hostName);
        request.CertificateExtensions.Add(names.Build());

        var now = TimeProvider.System.GetUtcNow();
        using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(30));

        // Kestrel needs the private key in a form the platform's TLS stack can use, which an exported PFX gives
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), password: null);
    }
}
