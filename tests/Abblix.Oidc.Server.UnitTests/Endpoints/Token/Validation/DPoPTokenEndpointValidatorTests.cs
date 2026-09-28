// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Nonces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.Features.DPoP;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="DPoPTokenEndpointValidator"/> covering the proof it validates without the grant:
/// mandatory vs opportunistic DPoP for a missing proof, the proof-validation failure path, and the RFC 9449
/// section 8 nonce challenge-response loop. The comparison with what the grant was bound to is
/// <see cref="DPoPBindingValidatorTests"/>'s, and the proof's own JWT structural / signature / claim-binding
/// checks are <see cref="ProofValidatorTests"/>'; this test mocks <see cref="IProofValidator"/>
/// to focus on the wiring between proof, nonce, and confirmation-stash decisions.
/// </summary>
public class DPoPTokenEndpointValidatorTests
{
    private const string ProofJwt = "eyJ.dummy.proof";
    private const string ProofKeyThumbprint = "test-jkt-thumbprint";
    private const string FreshNonce = "fresh-nonce-value";

    private static readonly DateTimeOffset ProofIssuedAt = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IProofValidator> _proofValidator = new(MockBehavior.Strict);
    private readonly Mock<INonceService> _nonceService = new(MockBehavior.Strict);
    private readonly Mock<IOptionsMonitor<OidcOptions>> _options = new(MockBehavior.Strict);
    private readonly OidcOptions _opts = new();
    private readonly DPoPTokenEndpointValidator _validator;

    public DPoPTokenEndpointValidatorTests()
    {
        _options.SetupGet(o => o.CurrentValue).Returns(_opts);

        _validator = new DPoPTokenEndpointValidator(
            Mock.Of<ILogger<DPoPTokenEndpointValidator>>(),
            _proofValidator.Object,
            _nonceService.Object,
            _options.Object);
    }

    [Fact]
    public async Task ValidateAsync_MissingHeaderClientRequiresDPoP_ReturnsInvalidDPoPProof()
    {
        var context = CreateContext(proofJwt: null, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertProofRejected(error, context);
    }

    [Fact]
    public async Task ValidateAsync_MissingHeaderClientOpportunistic_ReturnsNullAndLeavesThumbprintUnset()
    {
        var context = CreateContext(proofJwt: null, clientRequiresDPoP: false);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.Null(error);
        Assert.Null(context.ProofKeyThumbprint);
    }

    /// <summary>
    /// The per-client dpop_bound_access_tokens flag mandates DPoP specifically: an mTLS
    /// certificate-bound token does NOT satisfy it, so a missing proof is still rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MissingHeaderClientRequiresDPoPWithCertificate_ReturnsInvalidDPoPProof()
    {
        using var certificate = CreateCertificate();
        var context = CreateContext(
            proofJwt: null,
            clientRequiresDPoP: true,
            clientCertificate: certificate,
            tlsClientCertificateBoundAccessTokens: true);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertProofRejected(error, context);
    }

    [Fact]
    public async Task ValidateAsync_ValidProofClientOpportunistic_StashesThumbprint()
    {
        SetupProofValidatorSuccess(BuildProof());
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: false);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertProofStashed(error, context);
    }

    [Fact]
    public async Task ValidateAsync_ValidProofClientRequiresDPoP_StashesThumbprint()
    {
        SetupProofValidatorSuccess(BuildProof());
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertProofStashed(error, context);
    }

    [Fact]
    public async Task ValidateAsync_InvalidProof_ReturnsInvalidDPoPProof()
    {
        SetupProofValidatorFailure(new ProofError(ProofErrorReasons.SignatureInvalid));
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: false);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertProofRejected(error, context);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndMissing_ReturnsUseDPoPNonceError()
    {
        RequireNonceAtTokenEndpoint();
        SetupProofValidatorSuccess(BuildProof(nonceClaim: null));
        SetupNonceIssue();
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertNonceChallenge(error, context);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndStale_ReturnsUseDPoPNonceError()
    {
        RequireNonceAtTokenEndpoint();
        SetupProofValidatorSuccess(BuildProof(nonceClaim: "stale-nonce"));
        SetupNonceValidate("stale-nonce", NonceValidationFailure.OutOfWindow);
        SetupNonceIssue();
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertNonceChallenge(error, context);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndValid_StashesThumbprint()
    {
        RequireNonceAtTokenEndpoint();
        SetupProofValidatorSuccess(BuildProof(nonceClaim: "good-nonce"));
        SetupNonceValidate("good-nonce", failure: null);
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertProofStashed(error, context);
    }

    [Fact]
    public async Task ValidateAsync_NonceNotRequired_DoesNotInvokeNonceService()
    {
        // Default _opts.DPoP.Nonce.RequireAtTokenEndpoint == false. Strict mock: any call to
        // INonceService that wasn't set up would throw, so the absence of failure here is
        // proof that the validator did not consult the nonce-service.
        SetupProofValidatorSuccess(BuildProof(nonceClaim: "some-nonce"));
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: false);

        var error = await _validator.ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertProofStashed(error, context);
        _nonceService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A context with no grant resolved, which is the state this step runs in: any read of the grant here
    /// faults, so each row also shows the step can run before a device code or backchannel request is spent.
    /// </summary>
    private static TokenValidationContext CreateContext(
        string? proofJwt,
        bool clientRequiresDPoP,
        X509Certificate2? clientCertificate = null,
        bool tlsClientCertificateBoundAccessTokens = false)
    {
        var clientRequest = new ClientRequest { DPoPProof = proofJwt, ClientCertificate = clientCertificate };
        return new TokenValidationContext(new TokenRequest(), clientRequest)
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId)
            {
                RequireDPoP = clientRequiresDPoP,
                TlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens,
            },
        };
    }

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

    private static Proof BuildProof(string? nonceClaim = null)
    {
        var payloadJson = new JsonObject();
        if (nonceClaim is not null)
            payloadJson[IanaClaimTypes.Nonce] = nonceClaim;
        var token = new JsonWebToken { Payload = new JsonWebTokenPayload(payloadJson) };
        return new Proof(token, new OctetJsonWebKey(), ProofKeyThumbprint, "jti-1", ProofIssuedAt);
    }

    private void SetupProofValidatorSuccess(Proof proof) =>
        _proofValidator
            .Setup(v => v.ValidateAsync(ProofJwt, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<Proof, ProofError>)proof);

    private void SetupProofValidatorFailure(ProofError error) =>
        _proofValidator
            .Setup(v => v.ValidateAsync(ProofJwt, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<Proof, ProofError>)error);

    private void RequireNonceAtTokenEndpoint() => _opts.DPoP.Nonce.RequireAtTokenEndpoint = true;

    private void SetupNonceIssue() =>
        _nonceService
            .Setup(n => n.IssueAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(FreshNonce);

    private void SetupNonceValidate(string nonce, NonceValidationFailure? failure) =>
        _nonceService
            .Setup(n => n.ValidateAsync(nonce, It.IsAny<CancellationToken>()))
            .ReturnsAsync(failure);

    private static void AssertProofRejected(OidcError? error, TokenValidationContext context)
    {
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidDPoPProof, error.Error);
        Assert.Null(context.ProofKeyThumbprint);
    }

    private static void AssertProofStashed(OidcError? error, TokenValidationContext context)
    {
        Assert.Null(error);
        Assert.Equal(ProofKeyThumbprint, context.ProofKeyThumbprint);
    }

    private static void AssertNonceChallenge(OidcError? error, TokenValidationContext context)
    {
        var nonceError = Assert.IsType<UseDPoPNonceError>(error);
        Assert.Equal(ErrorCodes.UseDPoPNonce, nonceError.Error);
        Assert.Equal(FreshNonce, nonceError.Nonce);
        Assert.Null(context.ProofKeyThumbprint);
    }
}
