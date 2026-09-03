// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Validation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Nonces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;
using Abblix.Utils;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.UserInfo.Validation;

/// <summary>
/// Unit tests for <see cref="DPoPUserInfoValidator"/> covering the RFC 9449 section 7.1
/// resource-server enforcement matrix: scheme/binding alignment, proof presence,
/// proof-key thumbprint match against <c>cnf.jkt</c>, and the optional section 8 nonce
/// challenge-response loop. Mirrors the structure of
/// <see cref="DPoPTokenEndpointValidatorTests"/> - proof JWT structural / signature
/// checks belong to <c>ProofValidatorTests</c>, this suite mocks
/// <see cref="IProofValidator"/> to focus on the binding-decision wiring.
/// </summary>
public class DPoPUserInfoValidatorTests
{
    private const string ProofJwt = "eyJ.dummy.proof";
    private const string ProofKeyThumbprint = "test-jkt-thumbprint";
    private const string OtherThumbprint = "other-jkt-thumbprint";
    private const string AccessTokenJwt = "eyJ.access.token";
    private const string FreshNonce = "fresh-nonce-value";

    private static readonly DateTimeOffset ProofIssuedAt = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IProofValidator> _proofValidator = new(MockBehavior.Strict);
    private readonly Mock<INonceService> _nonceService = new(MockBehavior.Strict);
    private readonly Mock<IOptionsMonitor<OidcOptions>> _options = new(MockBehavior.Strict);
    private readonly OidcOptions _opts = new();
    private readonly DPoPUserInfoValidator _validator;

    public DPoPUserInfoValidatorTests()
    {
        _options.SetupGet(o => o.CurrentValue).Returns(_opts);

        _validator = new DPoPUserInfoValidator(
            Mock.Of<ILogger<DPoPUserInfoValidator>>(),
            _proofValidator.Object,
            _nonceService.Object,
            _options.Object);
    }

    [Fact]
    public async Task ValidateAsync_BearerTokenWithBearerScheme_ReturnsNull()
    {
        var token = BuildAccessToken(jwkThumbprint: null);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.Bearer, dpopProof: null);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.Null(error);
    }

    [Fact]
    public async Task ValidateAsync_BearerTokenWithDPoPScheme_ReturnsInvalidToken()
    {
        var token = BuildAccessToken(jwkThumbprint: null);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }

    [Fact]
    public async Task ValidateAsync_DPoPTokenWithBearerScheme_ReturnsInvalidToken()
    {
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.Bearer, dpopProof: null);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }

    [Fact]
    public async Task ValidateAsync_DPoPTokenWithoutProof_ReturnsInvalidDPoPProof()
    {
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: null);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.IsType<InvalidDPoPProofError>(error);
    }

    [Fact]
    public async Task ValidateAsync_ProofValidatorRejects_ReturnsInvalidDPoPProof()
    {
        SetupProofValidatorFailure(new ProofError("signature_invalid"));
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.IsType<InvalidDPoPProofError>(error);
    }

    [Fact]
    public async Task ValidateAsync_ProofKeyMismatch_ReturnsInvalidDPoPProof()
    {
        // Proof validates structurally but its key thumbprint does not match the cnf.jkt
        // committed on the access token - replay with a different key.
        SetupProofValidatorSuccess(BuildProof(thumbprint: OtherThumbprint));
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.IsType<InvalidDPoPProofError>(error);
    }

    [Fact]
    public async Task ValidateAsync_ValidProofKeyMatch_ReturnsNull()
    {
        SetupProofValidatorSuccess(BuildProof(thumbprint: ProofKeyThumbprint));
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.Null(error);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredButProofMissingNonce_ReturnsUseDPoPNonce()
    {
        RequireNonceAtUserInfoEndpoint();
        SetupNonceIssue();
        SetupProofValidatorSuccess(BuildProof(thumbprint: ProofKeyThumbprint, nonceClaim: null));
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        AssertNonceChallenge(error);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndStaleNonce_ReturnsUseDPoPNonce()
    {
        RequireNonceAtUserInfoEndpoint();
        SetupNonceIssue();
        SetupNonceValidate("stale-nonce", NonceValidationFailure.OutOfWindow);
        SetupProofValidatorSuccess(BuildProof(thumbprint: ProofKeyThumbprint, nonceClaim: "stale-nonce"));
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        AssertNonceChallenge(error);
    }

    [Fact]
    public async Task ValidateAsync_NonceRequiredAndFreshNonce_ReturnsNull()
    {
        RequireNonceAtUserInfoEndpoint();
        SetupNonceValidate("fresh", null);
        SetupProofValidatorSuccess(BuildProof(thumbprint: ProofKeyThumbprint, nonceClaim: "fresh"));
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.Null(error);
    }

    [Fact]
    public async Task ValidateAsync_NonceNotRequired_DoesNotInvokeNonceService()
    {
        // Default _opts.DPoP.Nonce.RequireAtUserInfoEndpoint == false. Strict mock proves
        // the validator does not consult INonceService when the policy is off.
        SetupProofValidatorSuccess(BuildProof(thumbprint: ProofKeyThumbprint, nonceClaim: "any"));
        var token = BuildAccessToken(jwkThumbprint: ProofKeyThumbprint);
        var clientRequest = BuildClientRequest(scheme: TokenTypes.DPoP, dpopProof: ProofJwt);

        var error = await _validator.ValidateAsync(clientRequest, token, AccessTokenJwt);

        Assert.Null(error);
        _nonceService.VerifyNoOtherCalls();
    }

    private static JsonWebToken BuildAccessToken(string? jwkThumbprint)
    {
        var token = new JsonWebToken();
        if (jwkThumbprint is not null)
        {
            token.Payload.Confirmation = new JsonWebTokenConfirmation
            {
                JwkThumbprint = jwkThumbprint,
            };
        }
        return token;
    }

    private static ClientRequest BuildClientRequest(string scheme, string? dpopProof)
        => new()
        {
            AuthorizationHeader = new AuthenticationHeaderValue(scheme, "opaque-access-token"),
            DPoPProof = dpopProof,
        };

    private static Proof BuildProof(string thumbprint, string? nonceClaim = null)
    {
        var payloadJson = new JsonObject();
        if (nonceClaim is not null)
            payloadJson[IanaClaimTypes.Nonce] = nonceClaim;
        var token = new JsonWebToken { Payload = new JsonWebTokenPayload(payloadJson) };
        return new Proof(token, new OctetJsonWebKey(), thumbprint, "jti-1", ProofIssuedAt);
    }

    private void SetupProofValidatorSuccess(Proof proof) =>
        _proofValidator
            .Setup(v => v.ValidateAsync(ProofJwt, AccessTokenJwt, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<Proof, ProofError>)proof);

    private void SetupProofValidatorFailure(ProofError error) =>
        _proofValidator
            .Setup(v => v.ValidateAsync(ProofJwt, AccessTokenJwt, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<Proof, ProofError>)error);

    private void RequireNonceAtUserInfoEndpoint() => _opts.DPoP.Nonce.RequireAtUserInfoEndpoint = true;

    private void SetupNonceIssue() =>
        _nonceService
            .Setup(n => n.IssueAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(FreshNonce);

    private void SetupNonceValidate(string nonce, NonceValidationFailure? failure) =>
        _nonceService
            .Setup(n => n.ValidateAsync(nonce, It.IsAny<CancellationToken>()))
            .ReturnsAsync(failure);

    private static void AssertNonceChallenge(OidcError? error)
    {
        var nonceError = Assert.IsType<UseDPoPNonceError>(error);
        Assert.Equal(ErrorCodes.UseDPoPNonce, nonceError.Error);
        Assert.Equal(FreshNonce, nonceError.Nonce);
    }
}
