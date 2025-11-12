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

using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Binds a client X.509 certificate from either the direct TLS connection
/// (HttpContext.Connection.ClientCertificate) or common forwarded headers
/// like X-Forwarded-Client-Cert / X-Client-Cert. Intended for use behind
/// a trusted reverse proxy that validates client certs and forwards them.
/// </summary>
public class ClientCertificateBinder : IModelBinder
{
    // Common header names used by proxies to forward client cert
    private static readonly string[] HeaderNames =
    {
        "X-Forwarded-Client-Cert",
        "X-Client-Cert"
    };

    public async Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var httpContext = bindingContext.HttpContext;

        // Prefer direct TLS client cert if available
        var clientCert = httpContext.Connection.ClientCertificate
                          ?? await httpContext.Connection.GetClientCertificateAsync();

        if (clientCert == null)
        {
            // Try forwarded headers
            foreach (var header in HeaderNames)
            {
                if (!httpContext.Request.Headers.TryGetValue(header, out var values))
                    continue;

                var value = values.ToString();
                if (string.IsNullOrWhiteSpace(value))
                    continue;

                // Attempt to parse PEM, Base64 (DER), or URL-decoded content
                try
                {
                    clientCert = TryParseCertificate(value);
                    if (clientCert != null)
                        break;
                }
                catch
                {
                    // ignore and continue
                }
            }
        }

        bindingContext.Result = ModelBindingResult.Success(clientCert);
        await Task.CompletedTask;
    }

    private static X509Certificate2? TryParseCertificate(string input)
    {
        // If looks like PEM
        if (input.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            var pem = input;
            return X509Certificate2.CreateFromPem(pem);
        }

        // Try URL-decoding then Base64
        try
        {
            var urlDecoded = Uri.UnescapeDataString(input);
            var der = Convert.FromBase64String(NormalizeBase64(urlDecoded));
            return new X509Certificate2(der);
        }
        catch
        {
            // fall-through
        }

        // Try raw Base64
        var bytes = Convert.FromBase64String(NormalizeBase64(input));
        return new X509Certificate2(bytes);
    }

    private static string NormalizeBase64(string value)
    {
        // Clean spaces and line breaks
        var cleaned = new StringBuilder();
        foreach (var ch in value)
        {
            if (!char.IsWhiteSpace(ch))
                cleaned.Append(ch);
        }

        // Pad base64 if needed
        var s = cleaned.ToString();
        var pad = s.Length % 4;
        if (pad > 0)
            s = s.PadRight(s.Length + (4 - pad), '=');
        return s;
    }
}

