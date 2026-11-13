// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.PushedAuthorization;

/// <summary>
/// Unit tests for <see cref="PushedAuthorizationRequestValidator"/> covering the new
/// RFC 9449 section 10 carry-over plumbing at the PAR endpoint: optional DPoP header
/// validation, equality check between header-derived thumbprint and the
/// <c>dpop_jkt</c> form parameter, back-fill behavior when only the header is
/// presented, and nonce-policy enforcement when the deployment opts in.
/// </summary>
public class PushedAuthorizationRequestValidatorTests
{
    private const string ProofJwt = "eyJ.dummy.proof";
    private const string DerivedThumbprint = "Wv1eDD8H4U6oOyVD0Y8GbqYAh8mXJTfjOcfZ4nVbA9Y";
    private const string DifferentThumbprint = "00000000000000000000000000000000000000000000";

    private static readonly DateTimeOffset ProofIssuedAt = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IAuthorizationRequestValidator> _innerValidator = new(MockBehavior.Strict);
    private readonly Mock<IClientAuthenticator> _clientAuthenticator = new(MockBehavior.Strict);
    private readonly Mock<IProofValidator> _proofValidator = new(MockBehavior.Strict);
    private readonly PushedAuthorizationRequestValidator _validator;

    public PushedAuthorizationRequestValidatorTests()
    {
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId));
        _innerValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.IsAny<AuthorizationRequest>()))
            .ReturnsAsync((TenantDefinition _, AuthorizationRequest req) =>
            {
                _capturedRequest = req;
                return (Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>)
                    new ValidAuthorizationRequest(
                        new AuthorizationValidationContext(req)
                        {
                            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
                            ResponseMode = ResponseModes.Query,
                            ValidRedirectUri = req.RedirectUri,
                        });
            });

        _validator = new PushedAuthorizationRequestValidator(
            _innerValidator.Object,
            _clientAuthenticator.Object,
            _proofValidator.Object);
    }

    private AuthorizationRequest? _capturedRequest;

    private static AuthorizationRequest BuildRequest(string? proofKeyThumbprint = null)
        => new()
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            ProofKeyThumbprint = proofKeyThumbprint,
        };

    private static ClientRequest BuildClientRequest(string? dpopProof = null)
        => new()
        {
            ClientId = TestConstants.DefaultClientId,
            DPoPProof = dpopProof,
        };

    private void SetupProofSuccess(string? nonceClaim = null)
    {
        var payloadJson = new JsonObject();
        if (nonceClaim is not null)
            payloadJson[IanaClaimTypes.Nonce] = nonceClaim;
        var token = new JsonWebToken { Payload = new JsonWebTokenPayload(payloadJson) };
        var proof = new Proof(token, new OctetJsonWebKey(), DerivedThumbprint, "jti-1", ProofIssuedAt);
        _proofValidator
            .Setup(v => v.ValidateAsync(It.IsAny<SecurityProfileRequirements>(), ProofJwt, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<Proof, ProofError>)proof);
    }

    private void SetupProofFailure(string reason = "signature_invalid")
        => _proofValidator
            .Setup(v => v.ValidateAsync(It.IsAny<SecurityProfileRequirements>(), ProofJwt, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<Proof, ProofError>)new ProofError(reason));

    /// <summary>
    /// RFC 9126 section 2.1: the request_uri parameter "MUST NOT be provided" in a pushed request, and section 2.3
    /// takes its codes from RFC 6749, where a request carrying it is malformed: invalid_request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RequestUriInThePushedRequest_ReturnsInvalidRequest()
    {
        var request = BuildRequest() with { RequestUri = new Uri("https://client.example.com/request.jwt") };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, request, BuildClientRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    [Fact]
    public async Task ValidateAsync_NoDPoPHeaderNoParameter_PassesThrough()
    {
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, BuildRequest(), BuildClientRequest());

        Assert.True(result.TryGetSuccess(out _));
        Assert.NotNull(_capturedRequest);
        Assert.Null(_capturedRequest.ProofKeyThumbprint);
    }

    [Fact]
    public async Task ValidateAsync_DPoPHeaderOnly_BackfillsThumbprintFromProof()
    {
        SetupProofSuccess();

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, BuildRequest(), BuildClientRequest(ProofJwt));

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(DerivedThumbprint, _capturedRequest?.ProofKeyThumbprint);
    }

    [Fact]
    public async Task ValidateAsync_DPoPHeaderAndMatchingParameter_PassesThrough()
    {
        SetupProofSuccess();

        var result = await _validator.ValidateAsync(
            SingleIssuer.Tenant,
            BuildRequest(proofKeyThumbprint: DerivedThumbprint),
            BuildClientRequest(ProofJwt));

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(DerivedThumbprint, _capturedRequest?.ProofKeyThumbprint);
    }

    [Fact]
    public async Task ValidateAsync_DPoPHeaderAndMismatchingParameter_ReturnsInvalidDPoPProof()
    {
        SetupProofSuccess();

        var result = await _validator.ValidateAsync(
            SingleIssuer.Tenant,
            BuildRequest(proofKeyThumbprint: DifferentThumbprint),
            BuildClientRequest(ProofJwt));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidDPoPProof, error.Error);
    }

    [Fact]
    public async Task ValidateAsync_InvalidDPoPHeader_ReturnsInvalidDPoPProof()
    {
        SetupProofFailure();

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, BuildRequest(), BuildClientRequest(ProofJwt));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidDPoPProof, error.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2: the server "shall require PAR requests, if supported, to use PKCE (RFC7636) with
    /// S256 as the code challenge method". A pushed request from a client held to that profile is refused without a
    /// code challenge or with the plain method, and passes with S256; a client held to no profile pushes without one.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, null, null, false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, "challenge", CodeChallengeMethods.Plain, false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, "challenge", CodeChallengeMethods.S256, true)]
    [InlineData(null, null, null, true)]
    public async Task ValidateAsync_Fapi1Advanced_RequiresPkceWithS256(
        ClientSecurityProfile? profile, string? challenge, string? method, bool accepted)
    {
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = profile });
        var request = BuildRequest() with { CodeChallenge = challenge, CodeChallengeMethod = method };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, request, BuildClientRequest());

        if (accepted)
            Assert.True(result.TryGetSuccess(out _));
        else
            Assert.Equal(ErrorCodes.InvalidRequest, Assert.IsType<AuthorizationRequestValidationError>(
                result.TryGetFailure(out var error) ? error : null).Error);
    }

    /// <summary>
    /// The same clauses at the pushed authorization request endpoint: the proof is judged under the profile of the
    /// client presenting it, which for FAPI 1.0 Advanced refuses a proof signed RS256 and admits one signed ES256.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, false)]
    [InlineData(SigningAlgorithms.ES256, true)]
    public async Task ValidateAsync_Fapi1Advanced_JudgesTheProofAlgorithm(string algorithm, bool accepted)
    {
        SecurityProfileRequirements? judgedUnder = null;
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = ClientSecurityProfile.Fapi1Advanced });
        var token = new JsonWebToken { Header = { Algorithm = algorithm } };
        _proofValidator
            .Setup(v => v.ValidateAsync(It.IsAny<SecurityProfileRequirements>(), ProofJwt, null, It.IsAny<CancellationToken>()))
            .Callback<SecurityProfileRequirements, string, string?, CancellationToken>(
                (profile, _, _, _) => judgedUnder = profile)
            .ReturnsAsync((Result<Proof, ProofError>)new Proof(
                token, new OctetJsonWebKey(), DerivedThumbprint, "jti-1", ProofIssuedAt));
        var request = BuildRequest() with
        {
            CodeChallenge = "challenge",
            CodeChallengeMethod = CodeChallengeMethods.S256,
        };

        await _validator.ValidateAsync(SingleIssuer.Tenant, request, BuildClientRequest(ProofJwt));

        Assert.Equal(accepted, judgedUnder!.PermitsSigningAlgorithm(algorithm));
    }
}
