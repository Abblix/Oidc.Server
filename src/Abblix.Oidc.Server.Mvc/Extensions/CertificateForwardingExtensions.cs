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
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.Extensions;

/// <summary>
/// Extension methods for configuring client certificate forwarding for mTLS support.
/// </summary>
public static class CertificateForwardingExtensions
{
    /// <summary>
    /// Adds certificate forwarding middleware for mTLS when behind a reverse proxy.
    /// WARNING: Only use when behind a TRUSTED reverse proxy that validates client certificates.
    /// Improper configuration can allow certificate spoofing attacks.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="headerName">
    /// The header name containing the client certificate.
    /// Common values: "X-Client-Cert" (nginx), "X-Forwarded-Client-Cert" (Envoy), "X-SSL-Client-Cert"
    /// </param>
    /// <param name="configure">Optional callback to customize certificate parsing logic.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// This method configures ASP.NET Core's built-in certificate forwarding with sensible defaults
    /// for common reverse proxy setups. The certificate can be in PEM or Base64-encoded DER format.
    ///
    /// After calling this method, add app.UseCertificateForwarding() to your middleware pipeline
    /// BEFORE app.UseAuthentication().
    ///
    /// Example:
    /// <code>
    /// services.AddMtlsCertificateForwarding("X-Client-Cert");
    ///
    /// // In middleware pipeline:
    /// app.UseCertificateForwarding(); // Before authentication
    /// app.UseAuthentication();
    /// </code>
    /// </remarks>
    public static IServiceCollection AddMtlsCertificateForwarding(
        this IServiceCollection services,
        string headerName = "X-Client-Cert",
        Action<CertificateForwardingOptions>? configure = null)
    {
        services.AddCertificateForwarding(options =>
        {
            options.CertificateHeader = headerName;
            options.HeaderConverter = headerValue =>
            {
                if (string.IsNullOrWhiteSpace(headerValue))
                    return null!;

                try
                {
                    // PEM format (nginx with ssl_client_escaped_cert)
                    if (headerValue.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                    {
                        return X509Certificate2.CreateFromPem(headerValue);
                    }

                    // Try URL-decoded then Base64 (common for nginx with ssl_client_cert)
                    try
                    {
                        return LoadCertificate2(Uri.UnescapeDataString(headerValue));
                    }
                    catch
                    {
                        // Try raw Base64 (Envoy, HAProxy)
                        return LoadCertificate2(headerValue);
                    }
                }
                catch
                {
                    // Invalid certificate format - return null to reject
                    return null!;
                }
            };

            configure?.Invoke(options);
        });

        return services;
    }

    /// <summary>
    /// Loads an X.509 certificate from Base64-encoded DER bytes.
    /// Uses the modern X509CertificateLoader API on .NET 9+ for better security and performance.
    /// </summary>
    /// <param name="value">Base64-encoded certificate data, potentially with whitespace.</param>
    /// <returns>The loaded X.509 certificate.</returns>
    /// <exception cref="FormatException">Thrown when the Base64 string is invalid.</exception>
    /// <exception cref="CryptographicException">Thrown when the certificate data is invalid.</exception>
    private static X509Certificate2 LoadCertificate2(string value)
    {
        var bytes = Convert.FromBase64String(NormalizeBase64(value));
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(bytes);
#else
        return new X509Certificate2(bytes);
#endif
    }

    /// <summary>
    /// Normalizes a Base64 string by removing whitespace and adding padding if needed.
    /// Ensures the string length is a multiple of 4 as required by Base64 specification.
    /// </summary>
    /// <param name="value">The Base64 string to normalize.</param>
    /// <returns>A properly formatted Base64 string with correct padding.</returns>
    private static string NormalizeBase64(string value)
    {
        // Remove whitespace and add padding if needed
        var cleaned = new string(value.Where(c => !char.IsWhiteSpace(c)).ToArray());
        var padding = cleaned.Length % 4;
        return padding == 0 ? cleaned : cleaned + new string('=', 4 - padding);
    }
}
