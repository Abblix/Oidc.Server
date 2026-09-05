// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// RFC 8705 tls_client_auth authenticator. Matches presented client certificate against
/// client metadata: subject DN and/or Subject Alternative Name entries.
/// </summary>
public partial class TlsMetadataClientAuthenticator(
    ILogger<TlsMetadataClientAuthenticator> logger,
    IClientInfoProvider clientInfoProvider) : IClientAuthenticator
{
    /// <summary>
    /// OID for Subject Alternative Name extension (RFC 5280 section 4.2.1.6).
    /// </summary>
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    /// <summary>
    /// Gets the collection of client authentication methods supported by this authenticator.
    /// </summary>
    /// <value>
    /// A collection containing <see cref="ClientAuthenticationMethods.TlsClientAuth"/>.
    /// </value>
    public IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.TlsClientAuth; }
    }

    /// <summary>
    /// Attempts to authenticate a client using mutual TLS with metadata-based certificate validation.
    /// Validates the client certificate against configured Subject DN and/or Subject Alternative Name entries.
    /// </summary>
    /// <param name="request">The client request containing the certificate and client ID to authenticate.</param>
    /// <returns>
    /// A task that returns the authenticated <see cref="ClientInfo"/> if successful; otherwise, null.
    /// Returns null if no certificate is provided, client not found, authentication method doesn't match,
    /// or certificate validation fails.
    /// </returns>
    /// <remarks>
    /// This method implements RFC 8705 tls_client_auth by:
    /// 1. Verifying a client certificate is present
    /// 2. Looking up client configuration by client_id
    /// 3. Checking the client uses tls_client_auth method
    /// 4. Validating certificate Subject DN (if configured)
    /// 5. Validating certificate SAN entries (if configured)
    /// </remarks>
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        var certificate = request.ClientCertificate;
        if (certificate == null)
            return null;

        var clientId = request.ClientId;
        if (!clientId.NotNullOrWhiteSpace())
            return null;

        var client = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        if (client == null)
            return null;

        if (client.TokenEndpointAuthMethod != ClientAuthenticationMethods.TlsClientAuth)
            return null;

        var options = client.TlsClientAuth;
        if (options == null)
        {
            LogNoTlsMetadataConfigured(clientId);
            return null;
        }

        if (!MatchSubjectDn(options.SubjectDn, certificate))
            return null;

        if (!MatchSans(options, certificate))
            return null;

        LogAuthenticated(clientId);
        return client;
    }

    /// <summary>
    /// Validates the certificate's Subject Distinguished Name against the required DN.
    /// Uses X500DistinguishedName for proper RFC 4514 parsing and binary comparison.
    /// </summary>
    /// <param name="requiredDn">The required Subject DN in RFC 4514 format, or null if not required.</param>
    /// <param name="cert">The client certificate to validate.</param>
    /// <returns>
    /// True if the DN matches or no DN is required; false if validation fails.
    /// Falls back to case-insensitive string comparison if DN parsing fails.
    /// </returns>
    private static bool MatchSubjectDn(string? requiredDn, X509Certificate2 cert)
    {
        if (string.IsNullOrWhiteSpace(requiredDn))
            return true; // no requirement

        // A case-insensitive string compare is deliberately NOT used as a fallback: DN string
        // equality is sensitive to attribute ordering, RDN spacing and encoding, so it both
        // false-negatives and (on case) matches too loosely - a security-weakening path. The
        // required DN is validated at registration time (TlsClientAuthValidator), so a parse
        // failure here can only mean a misconfigured client; authentication fails closed.
        X500DistinguishedName requiredX500Dn;
        try
        {
            requiredX500Dn = new X500DistinguishedName(requiredDn);
        }
        catch (CryptographicException)
        {
            return false;
        }

        // Compare the binary RFC 4514 representation for an exact match.
        return cert.SubjectName.RawData.AsSpan().SequenceEqual(requiredX500Dn.RawData);
    }

    /// <summary>
    /// Validates the certificate's Subject Alternative Name (SAN) entries against required values.
    /// Checks DNS names, URIs, IP addresses, and email addresses based on client configuration.
    /// </summary>
    /// <param name="options">The TLS client authentication options containing required SAN entries.</param>
    /// <param name="cert">The client certificate to validate.</param>
    /// <returns>
    /// True if all required SAN entries are present in the certificate or no SAN checks are configured;
    /// false if any required entry is missing or the certificate has no SAN extension.
    /// </returns>
    /// <remarks>
    /// SAN matching is case-insensitive for DNS names and emails.
    /// All configured SAN entries must be present in the certificate for validation to succeed.
    /// </remarks>
    private static bool MatchSans(TlsClientAuthOptions options, X509Certificate2 cert)
    {
        if (options.SanDns is not { Length: > 0 } &&
            options.SanUris is not { Length: > 0 } &&
            options.SanIps is not { Length: > 0 } &&
            options.SanEmails is not { Length: > 0 })
        {
            return true; // nothing to check
        }

        var san = GetSubjectAlternativeName(cert);
        if (san == null)
            return false;

        if (options.SanDns is { Length: > 0 } && !options.SanDns.All(d => san.DnsNames.Contains(d)))
            return false;

        if (options.SanUris is { Length: > 0 } && !options.SanUris.All(u => san.Uris.Contains(u)))
            return false;

        if (options.SanIps is { Length: > 0 } && !options.SanIps.All(ip => san.Ips.Contains(ip)))
            return false;

        if (options.SanEmails is { Length: > 0 } && !options.SanEmails.All(e => san.Emails.Contains(e)))
            return false;

        return true;

    }

    /// <summary>
    /// Represents parsed Subject Alternative Name entries from a certificate.
    /// Provides collections of DNS names, URIs, IP addresses, and email addresses.
    /// </summary>
    private sealed class SanEntries
    {
        /// <summary>
        /// Gets the collection of DNS names from the SAN extension.
        /// Comparison is case-insensitive per DNS standards.
        /// </summary>
        public HashSet<string> DnsNames { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Gets the collection of URIs from the SAN extension.
        /// </summary>
        public HashSet<Uri> Uris { get; } = new();

        /// <summary>
        /// Gets the collection of IP addresses (as strings) from the SAN extension.
        /// </summary>
        public HashSet<string> Ips { get; } = new();

        /// <summary>
        /// Gets the collection of email addresses from the SAN extension.
        /// Comparison is case-insensitive per email standards.
        /// </summary>
        public HashSet<string> Emails { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Extracts and parses Subject Alternative Name entries from a certificate.
    /// Locates the SAN extension and delegates to the extension parser.
    /// </summary>
    /// <param name="certificate">The certificate to extract SAN entries from.</param>
    /// <returns>
    /// A <see cref="SanEntries"/> object containing all parsed SAN entries,
    /// or null if the certificate has no SAN extension or parsing fails.
    /// </returns>
    private static SanEntries? GetSubjectAlternativeName(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.FirstOrDefault(
            ext => ext.Oid is { Value: SubjectAlternativeNameOid });

        if (extension == null)
            return null;

        try
        {
            return GetSubjectAlternativeName(extension);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parses Subject Alternative Name entries from a certificate extension using ASN.1 decoding.
    /// Extracts DNS names, URIs, IP addresses, and email addresses per RFC 5280.
    /// </summary>
    /// <param name="extension">The X.509 extension containing the SAN data.</param>
    /// <returns>
    /// A <see cref="SanEntries"/> object containing all parsed entries.
    /// Invalid URIs are silently skipped; all other entry types are included as-is.
    /// </returns>
    /// <remarks>
    /// Uses <see cref="AsnReader"/> for proper ASN.1 DER decoding, avoiding locale-dependent parsing.
    /// Unsupported GeneralName types (otherName, directoryName, x400Address, etc.) are skipped.
    /// </remarks>
    private static SanEntries GetSubjectAlternativeName(X509Extension extension)
    {
        var entries = new SanEntries();
        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);

        // SubjectAltName is a SEQUENCE OF GeneralName
        var sequenceReader = reader.ReadSequence();

        while (sequenceReader.HasData)
        {
            var tag = sequenceReader.PeekTag();

            switch ((GeneralNameTag)tag.TagValue)
            {
                case GeneralNameTag.Rfc822Name:
                    var email = Encoding.UTF8.GetString(sequenceReader.ReadOctetString(tag));
                    entries.Emails.Add(email);
                    break;

                case GeneralNameTag.DnsName:
                    var dns = Encoding.UTF8.GetString(sequenceReader.ReadOctetString(tag));
                    entries.DnsNames.Add(dns);
                    break;

                case GeneralNameTag.UniformResourceIdentifier:
                    var uriString = Encoding.UTF8.GetString(sequenceReader.ReadOctetString(tag));
                    if (Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
                        entries.Uris.Add(uri);
                    break;

                case GeneralNameTag.IpAddress:
                    var ipBytes = sequenceReader.ReadOctetString(tag);
                    var ip = new IPAddress(ipBytes).ToString();
                    entries.Ips.Add(ip);
                    break;

                default:
                    // Skip unsupported GeneralName types (otherName, directoryName, x400Address, etc.)
                    sequenceReader.ReadEncodedValue();
                    break;
            }
        }

        return entries;
    }
}
