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
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="SoftwareStatementValidator"/> verifying software statement
/// validation per RFC 7591 Section 2.3.
/// </summary>
public class SoftwareStatementValidatorTests
{
    private readonly OidcOptions _oidcOptions = new();
    private readonly Mock<IJsonWebTokenValidator> _jwtValidator = new();
    private readonly Mock<ISecureHttpFetcher> _secureFetcher = new();
    private readonly SoftwareStatementValidator _validator;

    public SoftwareStatementValidatorTests()
    {
        var optionsMonitor = new Mock<IOptionsMonitor<OidcOptions>>();
        optionsMonitor.Setup(m => m.CurrentValue).Returns(() => _oidcOptions);

        _validator = new SoftwareStatementValidator(
            _jwtValidator.Object,
            optionsMonitor.Object,
            _secureFetcher.Object,
            NullLogger<SoftwareStatementValidator>.Instance);
    }

    private static ClientRegistrationValidationContext CreateContext(string? softwareStatement = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            SoftwareStatement = softwareStatement,
        };
        return new ClientRegistrationValidationContext(request);
    }

    [Fact]
    public async Task ValidateAsync_WithNoSoftwareStatement_WhenNotRequired_ShouldReturnNull()
    {
        _oidcOptions.SoftwareStatement.RequireSoftwareStatement = false;

        var result = await _validator.ValidateAsync(CreateContext());
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithNoSoftwareStatement_WhenRequired_ShouldReturnError()
    {
        _oidcOptions.SoftwareStatement.RequireSoftwareStatement = true;

        var result = await _validator.ValidateAsync(CreateContext());

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidSoftwareStatement, result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WithSoftwareStatement_WhenNoTrustedIssuers_ShouldReturnError()
    {
        _oidcOptions.SoftwareStatement.TrustedIssuers = [];

        var result = await _validator.ValidateAsync(CreateContext("eyJ.fake.jwt"));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidSoftwareStatement, result.Error);
        Assert.Contains("No trusted issuers", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidJwt_ShouldReturnError()
    {
        _oidcOptions.SoftwareStatement.TrustedIssuers =
        [
            new TrustedIssuer
            {
                Issuer = "https://trusted-issuer.example.com",
                JwksUri = new Uri("https://trusted-issuer.example.com/.well-known/jwks.json"),
            },
        ];

        _jwtValidator
            .Setup(v => v.ValidateAsync("eyJ.invalid.jwt", It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Signature verification failed"));

        var result = await _validator.ValidateAsync(CreateContext("eyJ.invalid.jwt"));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidSoftwareStatement, result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WithValidJwt_AndNoApprovedSoftwareIds_ShouldReturnNull()
    {
        _oidcOptions.SoftwareStatement.TrustedIssuers =
        [
            new TrustedIssuer
            {
                Issuer = "https://trusted-issuer.example.com",
                JwksUri = new Uri("https://trusted-issuer.example.com/.well-known/jwks.json"),
            },
        ];
        _oidcOptions.SoftwareStatement.ApprovedSoftwareIds = [];

        var token = new JsonWebToken
        {
            Payload = new JsonWebTokenPayload(new JsonObject
            {
                ["software_id"] = "any-software",
            }),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync("eyJ.valid.jwt", It.IsAny<ValidationParameters>()))
            .ReturnsAsync(token);

        var result = await _validator.ValidateAsync(CreateContext("eyJ.valid.jwt"));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithApprovedSoftwareId_ShouldReturnNull()
    {
        _oidcOptions.SoftwareStatement.TrustedIssuers =
        [
            new TrustedIssuer
            {
                Issuer = "https://trusted-issuer.example.com",
                JwksUri = new Uri("https://trusted-issuer.example.com/.well-known/jwks.json"),
            },
        ];
        _oidcOptions.SoftwareStatement.ApprovedSoftwareIds = ["approved-app"];

        var token = new JsonWebToken
        {
            Payload = new JsonWebTokenPayload(new JsonObject
            {
                ["software_id"] = "approved-app",
            }),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync("eyJ.valid.jwt", It.IsAny<ValidationParameters>()))
            .ReturnsAsync(token);

        var result = await _validator.ValidateAsync(CreateContext("eyJ.valid.jwt"));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithUnapprovedSoftwareId_ShouldReturnError()
    {
        _oidcOptions.SoftwareStatement.TrustedIssuers =
        [
            new TrustedIssuer
            {
                Issuer = "https://trusted-issuer.example.com",
                JwksUri = new Uri("https://trusted-issuer.example.com/.well-known/jwks.json"),
            },
        ];
        _oidcOptions.SoftwareStatement.ApprovedSoftwareIds = ["approved-app"];

        var token = new JsonWebToken
        {
            Payload = new JsonWebTokenPayload(new JsonObject
            {
                ["software_id"] = "unapproved-app",
            }),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync("eyJ.valid.jwt", It.IsAny<ValidationParameters>()))
            .ReturnsAsync(token);

        var result = await _validator.ValidateAsync(CreateContext("eyJ.valid.jwt"));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnapprovedSoftwareStatement, result.Error);
        Assert.Contains("unapproved-app", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithMissingSoftwareIdClaim_WhenApprovedListConfigured_ShouldReturnError()
    {
        _oidcOptions.SoftwareStatement.TrustedIssuers =
        [
            new TrustedIssuer
            {
                Issuer = "https://trusted-issuer.example.com",
                JwksUri = new Uri("https://trusted-issuer.example.com/.well-known/jwks.json"),
            },
        ];
        _oidcOptions.SoftwareStatement.ApprovedSoftwareIds = ["approved-app"];

        var token = new JsonWebToken
        {
            Payload = new JsonWebTokenPayload(new JsonObject()),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync("eyJ.valid.jwt", It.IsAny<ValidationParameters>()))
            .ReturnsAsync(token);

        var result = await _validator.ValidateAsync(CreateContext("eyJ.valid.jwt"));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnapprovedSoftwareStatement, result.Error);
    }
}
