// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Abblix.Tests.Shared;

/// <summary>
/// A certificate authority of a test's own, issuing the client certificates a tls_client_auth client presents: a
/// self-signed root, optionally an intermediate under it, and leaf certificates under the last of them.
/// </summary>
public sealed class TestCertificateAuthority : IDisposable
{
    private const string ClientAuthenticationUsage = "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthenticationUsage = "1.3.6.1.5.5.7.3.1";
    private const int KeySize = 2048;
    private const int SerialNumberLength = 16;

    private readonly X509Certificate2 _issuer;

    private TestCertificateAuthority(X509Certificate2 root, X509Certificate2? intermediate)
    {
        Root = root;
        Intermediate = intermediate;
        _issuer = intermediate ?? root;
    }

    /// <summary>
    /// The self-signed root, a trust anchor.
    /// </summary>
    public X509Certificate2 Root { get; }

    /// <summary>
    /// The intermediate authority leaf certificates are issued under, or null when they are issued by the root.
    /// </summary>
    public X509Certificate2? Intermediate { get; }

    /// <summary>
    /// The root as a tenant lists it: base64-encoded DER.
    /// </summary>
    public string RootEncoded => Convert.ToBase64String(Root.RawData);

    /// <summary>
    /// The intermediate as a tenant lists it: base64-encoded DER.
    /// </summary>
    public string IntermediateEncoded
        => Convert.ToBase64String((Intermediate ?? throw new InvalidOperationException("No intermediate")).RawData);

    /// <summary>
    /// An authority whose root issues the leaf certificates itself.
    /// </summary>
    /// <param name="name">The root's subject.</param>
    public static TestCertificateAuthority Create(string name = "CN=Test Root CA")
        => new(CreateRoot(name), intermediate: null);

    /// <summary>
    /// An authority whose root issues an intermediate, which issues the leaf certificates.
    /// </summary>
    /// <param name="name">The root's subject.</param>
    public static TestCertificateAuthority CreateWithIntermediate(string name = "CN=Test Root CA")
    {
        var root = CreateRoot(name);
        using var key = RSA.Create(KeySize);
        var request = new CertificateRequest($"{name} Intermediate", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var now = TimeProvider.System.GetUtcNow();
        using var issued = request.Create(root, now.AddDays(-2), now.AddYears(2), SerialNumber());
        return new TestCertificateAuthority(root, issued.CopyWithPrivateKey(key));
    }

    /// <summary>
    /// A client certificate this authority issues for <paramref name="subject"/>, valid from
    /// <paramref name="notBefore"/> to <paramref name="notAfter"/> (a day back to a year ahead when not given).
    /// </summary>
    /// <param name="subject">The certificate's subject distinguished name.</param>
    /// <param name="configure">Adds extensions of the caller's, such as a subject alternative name.</param>
    /// <param name="notBefore">The start of the validity period.</param>
    /// <param name="notAfter">The end of the validity period.</param>
    /// <param name="serverOnly">Issues it for server authentication alone, an extended key usage that excludes a
    /// client.</param>
    public X509Certificate2 Issue(
        string subject,
        Action<CertificateRequest>? configure = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool serverOnly = false)
        => Issue(new X500DistinguishedName(subject), configure, notBefore, notAfter, serverOnly);

    /// <inheritdoc cref="Issue(string, Action{CertificateRequest}?, DateTimeOffset?, DateTimeOffset?, bool)"/>
    public X509Certificate2 Issue(
        X500DistinguishedName subject,
        Action<CertificateRequest>? configure = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool serverOnly = false)
    {
        using var key = RSA.Create(KeySize);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid(serverOnly ? ServerAuthenticationUsage : ClientAuthenticationUsage)], false));
        configure?.Invoke(request);

        var now = TimeProvider.System.GetUtcNow();
        using var issued = request.Create(
            _issuer, notBefore ?? now.AddDays(-1), notAfter ?? now.AddYears(1), SerialNumber());
        return issued.CopyWithPrivateKey(key);
    }

    /// <summary>
    /// A self-signed certificate for <paramref name="subject"/>, which no authority issued.
    /// </summary>
    /// <param name="subject">The certificate's subject distinguished name.</param>
    /// <param name="configure">Adds extensions of the caller's, such as a subject alternative name.</param>
    public static X509Certificate2 SelfSigned(string subject, Action<CertificateRequest>? configure = null)
    {
        using var key = RSA.Create(KeySize);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        configure?.Invoke(request);
        var now = TimeProvider.System.GetUtcNow();
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
    }

    private static X509Certificate2 CreateRoot(string name)
    {
        using var key = RSA.Create(KeySize);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var now = TimeProvider.System.GetUtcNow();
        return request.CreateSelfSigned(now.AddDays(-3), now.AddYears(3));
    }

    private static byte[] SerialNumber() => RandomNumberGenerator.GetBytes(SerialNumberLength);

    /// <inheritdoc />
    public void Dispose()
    {
        Root.Dispose();
        Intermediate?.Dispose();
    }
}
