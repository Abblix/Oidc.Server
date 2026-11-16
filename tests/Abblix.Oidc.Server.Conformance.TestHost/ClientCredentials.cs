// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// What the suite proves it is one static client with: a key it signs client assertions, request objects and DPoP
/// proofs with, and a self-signed certificate over the same key for mutual TLS.
/// </summary>
/// <remarks>
/// Minted afresh each time the host starts, so no private key is kept in the repository and no certificate outlives
/// the run it was made for. One key serves both credentials, since a self-signed client certificate is matched against
/// the client's registered key set (RFC 8705 section 2.2).
/// </remarks>
public sealed class ClientCredentials
{
    private ClientCredentials(JsonWebKey privateKey, string certificatePem, string privateKeyPem)
    {
        PrivateKey = privateKey;
        PublicKey = privateKey.Sanitize(includePrivateKeys: false);
        CertificatePem = certificatePem;
        PrivateKeyPem = privateKeyPem;
    }

    /// <summary>
    /// The key as the suite holds it, private members included.
    /// </summary>
    public JsonWebKey PrivateKey { get; }

    /// <summary>
    /// The key as the server registers it for the client.
    /// </summary>
    public JsonWebKey PublicKey { get; }

    /// <summary>
    /// The client's certificate, PEM-encoded.
    /// </summary>
    public string CertificatePem { get; }

    /// <summary>
    /// The certificate's private key, PEM-encoded as PKCS#8.
    /// </summary>
    public string PrivateKeyPem { get; }

    /// <summary>
    /// Mints the credentials of the client <paramref name="clientId"/>, its key declared for
    /// <paramref name="signingAlgorithm"/>: the suite signs with the algorithm a key declares.
    /// </summary>
    public static ClientCredentials Create(string clientId, string signingAlgorithm)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={clientId}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var now = TimeProvider.System.GetUtcNow();
        using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(30));

        var key = certificate.ToJsonWebKey(includePrivateKeys: true);
        key.KeyId = clientId;
        key.Algorithm = signingAlgorithm;
        return new ClientCredentials(key, certificate.ExportCertificatePem(), rsa.ExportPkcs8PrivateKeyPem());
    }
}
