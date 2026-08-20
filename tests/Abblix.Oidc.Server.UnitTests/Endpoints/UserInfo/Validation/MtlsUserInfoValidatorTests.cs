// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System;
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.UserInfo.Validation;

/// <summary>
/// Verifies RFC 8705 §3 resource-side enforcement of certificate-bound access tokens in
/// <see cref="MtlsUserInfoValidator"/>: a token carrying <c>cnf.x5t#S256</c> is accepted only
/// when the certificate presented on the mutual-TLS connection hashes to the bound value, and
/// rejected with <c>invalid_token</c> otherwise. Tokens without the binding pass through.
/// </summary>
public class MtlsUserInfoValidatorTests
{
    private readonly MtlsUserInfoValidator _validator = new();

    [Fact]
    public void UnboundToken_WithoutCertificate_IsAccepted()
    {
        // No cnf.x5t#S256 - a plain Bearer/DPoP token. The mTLS validator has nothing to
        // enforce and must not reject it even when no certificate is presented.
        var token = new JsonWebToken();
        var request = new ClientRequest();

        var result = _validator.Validate(request, token);

        Assert.Null(result);
    }

    [Fact]
    public void BoundToken_WithMatchingCertificate_IsAccepted()
    {
        using var certificate = CreateCertificate();
        var token = CreateBoundToken(ThumbprintOf(certificate));
        var request = new ClientRequest { ClientCertificate = certificate };

        var result = _validator.Validate(request, token);

        Assert.Null(result);
    }

    [Fact]
    public void BoundToken_WithoutCertificate_IsRejected()
    {
        // RFC 8705 §3: a certificate-bound token presented over a connection that carries no
        // client certificate must be rejected - the token is replayable otherwise.
        var token = CreateBoundToken("some-committed-thumbprint");
        var request = new ClientRequest();

        var result = _validator.Validate(request, token);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
    }

    [Fact]
    public void BoundToken_WithDifferentCertificate_IsRejected()
    {
        // The presented certificate is not the one the token was bound to (stolen-token replay
        // by a holder of a different certificate). RFC 8705 §3 requires rejection.
        using var boundCertificate = CreateCertificate();
        using var otherCertificate = CreateCertificate();
        var token = CreateBoundToken(ThumbprintOf(boundCertificate));
        var request = new ClientRequest { ClientCertificate = otherCertificate };

        var result = _validator.Validate(request, token);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
    }

    private static string ThumbprintOf(X509Certificate2 certificate) =>
        Base64Url.EncodeToString(SHA256.HashData(certificate.RawData));

    private static JsonWebToken CreateBoundToken(string thumbprint) =>
        new()
        {
            Payload =
            {
                Confirmation = new JsonWebTokenConfirmation { CertificateSha256Thumbprint = thumbprint },
            },
        };

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test Client",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var notBefore = DateTimeOffset.Parse("2025-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var notAfter = DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        return request.CreateSelfSigned(notBefore, notAfter);
    }
}
