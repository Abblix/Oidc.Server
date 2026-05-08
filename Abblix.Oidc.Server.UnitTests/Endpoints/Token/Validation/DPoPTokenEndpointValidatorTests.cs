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

using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Nonces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;

using Microsoft.Extensions.Options;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="DPoPTokenEndpointValidator"/> covering the four-way branch
/// (mandatory vs opportunistic × proof-present vs proof-missing), the proof-validation
/// failure path, and the RFC 9449 §8 nonce challenge-response loop. The validator's own
/// JWT structural / signature / claim-binding checks are out of scope here — those land
/// in <see cref="ProofValidatorTests"/>; this test mocks <see cref="IProofValidator"/>
/// to focus on the wiring between proof, nonce, and confirmation-stash decisions.
/// </summary>
public class DPoPTokenEndpointValidatorTests
{
    private const string TokenEndpointUri = "https://auth.example.com/token";
    private const string TokenEndpointMethod = "POST";
    private const string ProofJwt = "eyJ.dummy.proof";
    private const string ProofKeyThumbprint = "test-jkt-thumbprint";
    private const string FreshNonce = "fresh-nonce-value";

    private static readonly DateTimeOffset ProofIssuedAt = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IProofValidator> _proofValidator = new(MockBehavior.Strict);
    private readonly Mock<INonceService> _nonceService = new(MockBehavior.Strict);
    private readonly Mock<IRequestInfoProvider> _requestInfoProvider = new(MockBehavior.Strict);
    private readonly Mock<IOptionsMonitor<OidcOptions>> _options = new(MockBehavior.Strict);
    private readonly OidcOptions _opts = new();
    private readonly DPoPTokenEndpointValidator _validator;

    public DPoPTokenEndpointValidatorTests()
    {
        _requestInfoProvider.SetupGet(p => p.RequestUri).Returns(TokenEndpointUri);
        _requestInfoProvider.SetupGet(p => p.RequestMethod).Returns(TokenEndpointMethod);
        _options.SetupGet(o => o.CurrentValue).Returns(_opts);

        _validator = new DPoPTokenEndpointValidator(
            _proofValidator.Object,
            _nonceService.Object,
            _requestInfoProvider.Object,
            _options.Object);
    }

    [Fact]
    public async Task ValidateAsync_MissingHeaderClientRequiresDPoP_ReturnsInvalidDPoPProof()
    {
        var context = CreateContext(proofJwt: null, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context);

        AssertProofRejected(error, context);
    }

    [Fact]
    public async Task ValidateAsync_MissingHeaderClientOpportunistic_ReturnsNullAndLeavesThumbprintUnset()
    {
        var context = CreateContext(proofJwt: null, clientRequiresDPoP: false);

        var error = await _validator.ValidateAsync(context);

        Assert.Null(error);
        Assert.Null(context.ProofKeyThumbprint);
    }

    [Fact]
    public async Task ValidateAsync_ValidProofClientOpportunistic_StashesThumbprint()
    {
        SetupProofValidatorSuccess(BuildProof());
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: false);

        var error = await _validator.ValidateAsync(context);

        AssertProofStashed(error, context);
    }

    [Fact]
    public async Task ValidateAsync_ValidProofClientRequiresDPoP_StashesThumbprint()
    {
        SetupProofValidatorSuccess(BuildProof());
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context);

        AssertProofStashed(error, context);
    }

    [Fact]
    public async Task ValidateAsync_InvalidProof_ReturnsInvalidDPoPProof()
    {
        SetupProofValidatorFailure(new ProofError(ProofErrorReasons.SignatureInvalid));
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: false);

        var error = await _validator.ValidateAsync(context);

        AssertProofRejected(error, context);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndMissing_ReturnsDPoPNonceRequiredError()
    {
        RequireNonceAtTokenEndpoint();
        SetupProofValidatorSuccess(BuildProof(nonceClaim: null));
        SetupNonceIssue();
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context);

        AssertNonceChallenge(error, context);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndStale_ReturnsDPoPNonceRequiredError()
    {
        RequireNonceAtTokenEndpoint();
        SetupProofValidatorSuccess(BuildProof(nonceClaim: "stale-nonce"));
        SetupNonceValidate("stale-nonce", NonceValidationFailure.OutOfWindow);
        SetupNonceIssue();
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context);

        AssertNonceChallenge(error, context);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndValid_StashesThumbprint()
    {
        RequireNonceAtTokenEndpoint();
        SetupProofValidatorSuccess(BuildProof(nonceClaim: "good-nonce"));
        SetupNonceValidate("good-nonce", failure: null);
        var context = CreateContext(proofJwt: ProofJwt, clientRequiresDPoP: true);

        var error = await _validator.ValidateAsync(context);

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

        var error = await _validator.ValidateAsync(context);

        AssertProofStashed(error, context);
        _nonceService.VerifyNoOtherCalls();
    }

    private static TokenValidationContext CreateContext(string? proofJwt, bool clientRequiresDPoP)
    {
        var clientRequest = new ClientRequest { DPoPProof = proofJwt };
        return new TokenValidationContext(new TokenRequest(), clientRequest)
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId)
            {
                RequireDPoP = clientRequiresDPoP,
            },
        };
    }

    private static Proof BuildProof(string? nonceClaim = null)
    {
        var payloadJson = new JsonObject();
        if (nonceClaim is not null)
            payloadJson["nonce"] = nonceClaim;
        var token = new JsonWebToken { Payload = new JsonWebTokenPayload(payloadJson) };
        return new Proof(token, new OctetJsonWebKey(), ProofKeyThumbprint, "jti-1", ProofIssuedAt);
    }

    private void SetupProofValidatorSuccess(Proof proof) =>
        _proofValidator
            .Setup(v => v.ValidateAsync(ProofJwt, TokenEndpointMethod, It.IsAny<Uri>(), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<Proof, ProofError>)proof);

    private void SetupProofValidatorFailure(ProofError error) =>
        _proofValidator
            .Setup(v => v.ValidateAsync(ProofJwt, TokenEndpointMethod, It.IsAny<Uri>(), null, It.IsAny<CancellationToken>()))
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
        var nonceError = Assert.IsType<DPoPNonceRequiredError>(error);
        Assert.Equal(ErrorCodes.UseDPoPNonce, nonceError.Error);
        Assert.Equal(FreshNonce, nonceError.Nonce);
        Assert.Null(context.ProofKeyThumbprint);
    }
}
