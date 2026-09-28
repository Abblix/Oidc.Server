// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="DPoPBindingValidator"/>: the request against the key or certificate its grant was
/// bound to, and the sender-constrained token a security profile demands. The proof itself is validated by
/// <see cref="DPoPTokenEndpointValidator"/>, so each context here carries the proof key that step would have
/// left, or none when no proof was presented.
/// </summary>
public class DPoPBindingValidatorTests
{
    private const string ProofKeyThumbprint = "test-jkt-thumbprint";

    private static readonly DateTimeOffset IssuedAt = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    private readonly OidcOptions _opts = new();
    private readonly DPoPBindingValidator _validator;

    public DPoPBindingValidatorTests()
    {
        var options = new Mock<IOptionsMonitor<OidcOptions>>(MockBehavior.Strict);
        options.SetupGet(o => o.CurrentValue).Returns(_opts);

        _validator = new DPoPBindingValidator(Mock.Of<ILogger<DPoPBindingValidator>>(), options.Object);
    }

    /// <summary>
    /// A FAPI 2.0 client requires a sender-constrained token even when its per-client RequireDPoP flag
    /// is unset: the profile mandates DPoP and the granular toggle cannot weaken it. A missing proof
    /// is therefore rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MissingProofFapi2Client_ReturnsInvalidDPoPProof()
    {
        var context = CreateContext(presentedThumbprint: null, securityProfile: ClientSecurityProfile.Fapi2);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertInvalidProof(error);
    }

    /// <summary>
    /// A FAPI 2.0 client that sender-constrains via mutual TLS (a certificate-bound token, RFC 8705
    /// section 3) satisfies the profile without a DPoP proof: the missing proof is accepted because the
    /// issued token will be certificate-bound. FAPI 2.0 permits either mechanism.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MissingProofFapi2ClientWithCertificateBoundToken_ReturnsNull()
    {
        using var certificate = CreateCertificate();
        var context = CreateContext(
            presentedThumbprint: null,
            securityProfile: ClientSecurityProfile.Fapi2,
            clientCertificate: certificate,
            tlsClientCertificateBoundAccessTokens: true);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.Null(error);
    }

    /// <summary>
    /// A client that states no profile inherits the server-wide DefaultSecurityProfile=FAPI 2.0, which
    /// requires sender-constraining, so a missing proof is rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MissingProofGlobalDefaultFapi2_ReturnsInvalidDPoPProof()
    {
        _opts.DefaultSecurityProfile = ClientSecurityProfile.Fapi2;
        var context = CreateContext(presentedThumbprint: null, securityProfile: null);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertInvalidProof(error);
    }

    /// <summary>
    /// A client selecting None under a server-wide FAPI 2.0 default is still held to it, so a missing
    /// proof is refused rather than treated as opportunistic. The profile demands a
    /// sender-constrained token of every client the deployment serves, and a registration naming a
    /// profile that demands nothing adds nothing to that.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MissingProofExplicitNoneUnderGlobalDefaultFapi2_StillRefuses()
    {
        _opts.DefaultSecurityProfile = ClientSecurityProfile.Fapi2;
        var context = CreateContext(presentedThumbprint: null, securityProfile: ClientSecurityProfile.None);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertInvalidProof(error);
    }

    [Fact]
    public async Task ValidateAsync_MissingProofNothingBound_ReturnsNull()
    {
        var context = CreateContext(presentedThumbprint: null);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.Null(error);
    }

    [Fact]
    public async Task ValidateAsync_CommittedMatchesProof_ReturnsNull()
    {
        var context = CreateContext(presentedThumbprint: ProofKeyThumbprint, committedThumbprint: ProofKeyThumbprint);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.Null(error);
    }

    [Fact]
    public async Task ValidateAsync_CommittedMismatchesProof_ReturnsInvalidDPoPProof()
    {
        var context = CreateContext(
            presentedThumbprint: ProofKeyThumbprint,
            committedThumbprint: "different-committed-thumbprint");

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertInvalidProof(error);
    }

    [Fact]
    public async Task ValidateAsync_CommittedButNoProof_ReturnsInvalidDPoPProof()
    {
        // RFC 9449 section 10 carry-over: dpop_jkt was committed at /authorize but the client
        // tries to redeem the auth code without a DPoP proof. This is the canonical
        // attack window the carry-over closes.
        var context = CreateContext(
            presentedThumbprint: null,
            committedThumbprint: "committed-thumbprint-from-authorize");

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertInvalidProof(error);
    }

    /// <summary>
    /// RFC 8705 section 4: a certificate-bound grant redeemed by a non-mTLS client that presents no certificate
    /// must be rejected with invalid_grant - otherwise a stolen certificate-bound refresh token is
    /// redeemable with no certificate at all.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CertBoundGrant_NonMtlsClient_NoCertificate_ReturnsInvalidGrant()
    {
        var context = CreateContext(
            presentedThumbprint: null,
            committedCertThumbprint: "committed-x5t-s256",
            tokenEndpointAuthMethod: ClientAuthenticationMethods.None);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }

    /// <summary>
    /// A non-mTLS client that re-presents the same certificate the grant is bound to passes the RFC 8705
    /// section 4 binding check (and, with no DPoP proof required, the request is accepted).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CertBoundGrant_NonMtlsClient_MatchingCertificate_ReturnsNull()
    {
        using var certificate = CreateCertificate();
        var context = CreateContext(
            presentedThumbprint: null,
            clientCertificate: certificate,
            committedCertThumbprint: CertThumbprint(certificate),
            tokenEndpointAuthMethod: ClientAuthenticationMethods.None);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.Null(error);
    }

    /// <summary>
    /// A client that authenticates with mutual TLS is skipped: its authentication already proved
    /// certificate possession on the connection, so the binding check does not additionally demand the
    /// certificate be re-presented here.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CertBoundGrant_MutualTlsClient_NoCertificate_ReturnsNull()
    {
        var context = CreateContext(
            presentedThumbprint: null,
            committedCertThumbprint: "committed-x5t-s256",
            tokenEndpointAuthMethod: ClientAuthenticationMethods.TlsClientAuth);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.Null(error);
    }

    private static TokenValidationContext CreateContext(
        string? presentedThumbprint,
        string? committedThumbprint = null,
        ClientSecurityProfile? securityProfile = null,
        X509Certificate2? clientCertificate = null,
        bool tlsClientCertificateBoundAccessTokens = false,
        string? committedCertThumbprint = null,
        string? tokenEndpointAuthMethod = null)
    {
        var clientRequest = new ClientRequest { ClientCertificate = clientCertificate };
        var authContext = new AuthorizationContext(TestConstants.DefaultClientId, [], null)
        {
            ProofKeyThumbprint = committedThumbprint,
            CertificateSha256Thumbprint = committedCertThumbprint,
        };
        var authSession = new AuthSession("user-1", "session-1", IssuedAt, "local");
        return new TokenValidationContext(new TokenRequest(), clientRequest)
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = securityProfile,
                TlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens,
                TokenEndpointAuthMethod = tokenEndpointAuthMethod!,
            },
            AuthorizedGrant = new AuthorizedGrant(authSession, authContext),
            ProofKeyThumbprint = presentedThumbprint,
        };
    }

    private static string CertThumbprint(X509Certificate2 certificate)
        => Base64Url.EncodeToString(SHA256.HashData(certificate.RawData));

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

    private static void AssertInvalidProof(OidcError? error)
    {
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidDPoPProof, error.Error);
    }
}
