// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// The certificate authorities a tenant trusts for <c>tls_client_auth</c>
/// (<see cref="TenantDefinition.TlsClientAuthCertificateAuthorities"/>): whether the tenant serves the method at all,
/// whether a presented client certificate chains to them, and why a list of them cannot be served.
/// </summary>
/// <remarks>
/// The one answer discovery, registration and the authenticator take, so a tenant never names the method in its
/// discovery document while refusing every client using it, or the reverse.
/// </remarks>
internal static class TlsClientAuthCertificateAuthorities
{
    /// <summary>
    /// The extended key usage a client certificate is issued for when it names any (RFC 5280 section 4.2.1.12,
    /// id-kp-clientAuth: "TLS WWW client authentication").
    /// </summary>
    private const string ClientAuthenticationUsage = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// Whether <paramref name="tenant"/> serves <paramref name="authenticationMethod"/>: every method but
    /// <c>tls_client_auth</c>, and that one only where the tenant lists certificate authorities for it, since without
    /// them no client certificate can be validated (RFC 8705 section 2.1).
    /// </summary>
    /// <param name="tenant">The tenant asked about.</param>
    /// <param name="authenticationMethod">The client authentication method.</param>
    public static bool Serve(TenantDefinition tenant, string authenticationMethod)
        => authenticationMethod != ClientAuthenticationMethods.TlsClientAuth ||
           tenant.TlsClientAuthCertificateAuthorities.Count > 0;

    /// <summary>
    /// Why <paramref name="certificate"/> is not validated against the certificate authorities of
    /// <paramref name="tenant"/> at <paramref name="now"/>, or null when it is.
    /// </summary>
    /// <remarks>
    /// RFC 8705 section 2.1 has the PKI method rely "on a validated certificate chain [RFC5280]", built here against
    /// the tenant's authorities alone, whatever the TLS layer or a proxy in front of it accepted. The chain ends at a
    /// self-signed authority the tenant lists and passes only through those it lists, each element above the client's
    /// certificate compared with them, since the platform's chain engine may also take an intermediate from a
    /// certificate store of the host. Only the client's own certificate reaches the server. Nothing is downloaded: the addresses a certificate names for its
    /// issuers are written by whoever made it. Revocation is not checked, which section 2.1 leaves "a deployment
    /// decision at the discretion of the authorization server". A certificate naming extended key usages names
    /// client authentication among them.
    /// </remarks>
    /// <param name="tenant">The tenant whose authorities the chain must end at.</param>
    /// <param name="certificate">The client certificate presented.</param>
    /// <param name="now">The time the certificates' validity periods are judged at.</param>
    public static string? WhyNotChained(TenantDefinition tenant, X509Certificate2 certificate, DateTimeOffset now)
        => WhyNotChained(tenant, certificate, now, []);

    /// <summary>
    /// <see cref="WhyNotChained(TenantDefinition, X509Certificate2, DateTimeOffset)"/>, with
    /// <paramref name="found"/> standing for the certificates the chain engine finds beside the tenant's list, as a
    /// certificate store of the host would supply them.
    /// </summary>
    /// <param name="tenant">The tenant whose authorities the chain must end at.</param>
    /// <param name="certificate">The client certificate presented.</param>
    /// <param name="now">The time the certificates' validity periods are judged at.</param>
    /// <param name="found">Certificates the chain may be built through that the tenant does not list.</param>
    internal static string? WhyNotChained(
        TenantDefinition tenant, X509Certificate2 certificate, DateTimeOffset now, IEnumerable<X509Certificate2> found)
    {
        var authorities = Load(tenant.TlsClientAuthCertificateAuthorities);
        try
        {
            using var chain = new X509Chain();
            var policy = chain.ChainPolicy;
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.DisableCertificateDownloads = true;
            policy.RevocationMode = X509RevocationMode.NoCheck;
            policy.VerificationTime = now.UtcDateTime;
            policy.VerificationTimeIgnored = false;
            policy.ApplicationPolicy.Add(new Oid(ClientAuthenticationUsage));

            foreach (var authority in authorities)
            {
                if (IsSelfSigned(authority))
                    policy.CustomTrustStore.Add(authority);
                else
                    policy.ExtraStore.Add(authority);
            }

            foreach (var other in found)
                policy.ExtraStore.Add(other);

            if (!chain.Build(certificate))
                return string.Join(", ", chain.ChainStatus.Select(status => status.Status).Distinct());

            if (chain.ChainElements.Skip(1).All(element => IsListed(element.Certificate, authorities)))
                return null;

            return "the chain passes through an authority the tenant does not list";
        }
        finally
        {
            foreach (var authority in authorities)
                authority.Dispose();
        }
    }

    /// <summary>
    /// Why the certificate authorities a tenant lists cannot be served, each reason, or none when they can: each one
    /// is a certificate authority's certificate, and at least one is self-signed, so a chain can end somewhere.
    /// </summary>
    /// <param name="authorities">The list the tenant declares.</param>
    public static IEnumerable<string> Refusals(IReadOnlyCollection<string> authorities)
    {
        if (authorities.Count == 0)
            yield break;

        var anchors = 0;
        var index = 0;
        foreach (var value in authorities)
        {
            var refusal = Refusal(value, ref anchors);
            if (refusal is not null)
                yield return $"{Setting}[{index}] {refusal}";

            index++;
        }

        if (anchors == 0)
        {
            yield return $"{Setting} lists no self-signed certificate, so no chain can end at a trust anchor.";
        }
    }

    private const string Setting = nameof(TenantDefinition.TlsClientAuthCertificateAuthorities);

    private static string? Refusal(string value, ref int anchors)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(value));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return "is not a base64-encoded DER certificate.";
        }

        using (certificate)
        {
            if (certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()
                is not { CertificateAuthority: true })
            {
                return "is not the certificate of a certificate authority.";
            }

            if (IsSelfSigned(certificate))
                anchors++;

            return null;
        }
    }

    /// <summary>
    /// The listed certificates, each one loaded; the list was judged when the tenant entered the server, so every
    /// entry loads.
    /// </summary>
    private static X509Certificate2[] Load(IReadOnlyCollection<string> authorities)
        => [..authorities.Select(value => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(value)))];

    /// <summary>
    /// Whether <paramref name="certificate"/> is one of <paramref name="authorities"/>, by its encoding.
    /// </summary>
    private static bool IsListed(X509Certificate2 certificate, X509Certificate2[] authorities)
        => authorities.Any(authority => authority.RawData.AsSpan().SequenceEqual(certificate.RawData));

    /// <summary>
    /// A self-signed certificate names itself as its issuer, which is what makes it the end of a chain.
    /// </summary>
    private static bool IsSelfSigned(X509Certificate2 certificate)
        => certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
}
