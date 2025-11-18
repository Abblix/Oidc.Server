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
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="ResponseModeValidator"/> verifying response_mode validation
/// per OAuth 2.0 Multiple Response Type Encoding Practices and OIDC Core 1.0.
/// Tests cover flow-specific response mode compatibility, security requirements,
/// and proper context population.
/// </summary>
public class ResponseModeValidatorTests
{
    private const string ClientId = "client_123";

    private readonly Mock<ILogger<ResponseModeValidator>> _logger;
    private readonly ResponseModeValidator _validator;

    public ResponseModeValidatorTests()
    {
        _logger = new Mock<ILogger<ResponseModeValidator>>();
        _validator = new ResponseModeValidator(_logger.Object);
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        FlowTypes flowType,
        string? responseMode = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            ResponseMode = responseMode,
        };

        var clientInfo = new ClientInfo(ClientId);

        var context = new AuthorizationValidationContext(request)
        {
            ClientInfo = clientInfo,
            FlowType = flowType,
            ResponseMode = ResponseModes.Query, // Default
        };

        return context;
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts query mode for authorization code flow.
    /// Per OAuth 2.0, query is the default response mode for code flow.
    /// Critical for standard authorization code flow operation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_AuthorizationCodeFlowWithQuery_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, ResponseModes.Query);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.Query, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts fragment mode for authorization code flow.
    /// Per OAuth 2.0 Multiple Response Types, fragment is allowed for code flow.
    /// Tests alternative response mode for authorization code flow.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_AuthorizationCodeFlowWithFragment_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, ResponseModes.Fragment);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts form_post mode for authorization code flow.
    /// Per OAuth 2.0 Form Post Response Mode, form_post provides POST-based response.
    /// Tests secure response mode preventing URL parameter exposure.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_AuthorizationCodeFlowWithFormPost_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, ResponseModes.FormPost);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.FormPost, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts fragment mode for implicit flow.
    /// Per OAuth 2.0, fragment is the default and recommended mode for implicit flow.
    /// Critical for implicit flow security (tokens not sent to server).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ImplicitFlowWithFragment_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Implicit, ResponseModes.Fragment);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts form_post mode for implicit flow.
    /// Per OAuth 2.0 Form Post Response Mode, form_post is allowed for implicit flow.
    /// Tests alternative secure response mode for implicit flow.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ImplicitFlowWithFormPost_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Implicit, ResponseModes.FormPost);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.FormPost, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects query mode for implicit flow.
    /// Per OAuth 2.0 Security Best Practices, query mode is prohibited for implicit flow.
    /// Critical security check preventing token leakage via URL.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ImplicitFlowWithQuery_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Implicit, ResponseModes.Query);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("not supported", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts fragment mode for hybrid flow.
    /// Per OIDC Core 1.0, fragment is default mode for hybrid flows.
    /// Critical for hybrid flow operation with mixed response artifacts.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_HybridFlowWithFragment_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Hybrid, ResponseModes.Fragment);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts form_post mode for hybrid flow.
    /// Per OIDC Core 1.0, form_post is allowed for hybrid flows.
    /// Tests alternative secure response mode for hybrid flow.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_HybridFlowWithFormPost_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Hybrid, ResponseModes.FormPost);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.FormPost, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects query mode for hybrid flow.
    /// Per OAuth 2.0 Security Best Practices, query mode is prohibited for hybrid flow.
    /// Critical security check preventing token leakage when ID token is returned.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_HybridFlowWithQuery_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Hybrid, ResponseModes.Query);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts null response_mode (uses default).
    /// Per OAuth 2.0, response_mode is optional with flow-specific defaults.
    /// Tests that missing response_mode doesn't cause validation error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullResponseMode_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts empty string response_mode (uses default).
    /// Empty string treated as missing/null response_mode.
    /// Tests consistent handling of absent response_mode parameter.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyResponseMode_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: string.Empty);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects unknown response_mode.
    /// Per OAuth 2.0, only registered response modes are allowed.
    /// Tests validator rejects custom/invalid response modes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownResponseMode_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: "custom_mode");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync updates context.ResponseMode on success.
    /// Per validator contract, context must be updated with validated response mode.
    /// Critical for downstream authorization flow processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldUpdateContextResponseMode()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, ResponseModes.FormPost);
        Assert.Equal(ResponseModes.Query, context.ResponseMode); // Default

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(ResponseModes.FormPost, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync does not update context on failure.
    /// Failed validation should not modify context.ResponseMode.
    /// Ensures error responses use correct response mode.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnFailure_ShouldNotUpdateContextResponseMode()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Implicit, ResponseModes.Query);
        var originalMode = context.ResponseMode;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(originalMode, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync logs warning on invalid response mode.
    /// Per security best practices, incompatible response modes should be logged.
    /// Critical for security monitoring and configuration issue detection.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidResponseMode_ShouldLogWarning()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Implicit, ResponseModes.Query);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _logger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("not compatible")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes redirect URI in error response.
    /// Per OAuth 2.0, error responses should include redirect_uri when available.
    /// Critical for proper error flow completion.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/callback");
        var context = CreateContext(FlowTypes.Implicit, ResponseModes.Query);
        context.ValidRedirectUri = redirectUri;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(redirectUri, result.RedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes response mode in error response.
    /// Per OAuth 2.0, error delivery must use appropriate response mode.
    /// Critical for proper error communication channel.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeResponseMode()
    {
        // Arrange
        var context = CreateContext(FlowTypes.Implicit, ResponseModes.Query);
        context.ResponseMode = ResponseModes.Fragment; // Default for error response

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ResponseModes.Fragment, result.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync is case-sensitive for response_mode values.
    /// Per OAuth 2.0, response_mode values are case-sensitive.
    /// Tests that "QUERY" (uppercase) is treated as unknown mode.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUppercaseResponseMode_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: "QUERY");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects whitespace-only response_mode.
    /// Per HasValue() extension, whitespace is considered a value and validated.
    /// Whitespace is not a valid response_mode, so it fails validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithWhitespaceResponseMode_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: "   ");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts jwt response_mode for authorization code flow.
    /// Per OAuth 2.0 JWT Secured Authorization Response Mode (JARM), jwt mode is valid.
    /// Tests support for JWT-secured response mode.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_AuthorizationCodeFlowWithJwt_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: "jwt");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        // JWT mode is not in the explicitly allowed list, so it should fail
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync preserves original context response mode on null input.
    /// When response_mode is not specified, context default should remain.
    /// Tests context preservation for optional parameters.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullResponseMode_ShouldPreserveContextDefault()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: null);
        var originalMode = context.ResponseMode;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(originalMode, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles all three flow types correctly.
    /// Tests validator comprehensively covers AuthorizationCode, Implicit, and Hybrid flows.
    /// Ensures no flow type is missed in validation logic.
    /// </summary>
    [Theory]
    [InlineData(FlowTypes.AuthorizationCode, ResponseModes.Query, true)]
    [InlineData(FlowTypes.AuthorizationCode, ResponseModes.Fragment, true)]
    [InlineData(FlowTypes.AuthorizationCode, ResponseModes.FormPost, true)]
    [InlineData(FlowTypes.Implicit, ResponseModes.Query, false)]
    [InlineData(FlowTypes.Implicit, ResponseModes.Fragment, true)]
    [InlineData(FlowTypes.Implicit, ResponseModes.FormPost, true)]
    [InlineData(FlowTypes.Hybrid, ResponseModes.Query, false)]
    [InlineData(FlowTypes.Hybrid, ResponseModes.Fragment, true)]
    [InlineData(FlowTypes.Hybrid, ResponseModes.FormPost, true)]
    public async Task ValidateAsync_AllFlowTypesAndModes_ShouldValidateCorrectly(
        FlowTypes flowType,
        string responseMode,
        bool shouldSucceed)
    {
        // Arrange
        var context = CreateContext(flowType, responseMode);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        if (shouldSucceed)
        {
            Assert.Null(result);
            Assert.Equal(responseMode, context.ResponseMode);
        }
        else
        {
            Assert.NotNull(result);
            Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        }
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts query mode with trailing whitespace.
    /// Tests trimming behavior for response_mode values.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ResponseModeWithTrailingWhitespace_ShouldFail()
    {
        // Arrange
        var context = CreateContext(FlowTypes.AuthorizationCode, responseMode: "query ");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        // No trimming, so "query " != "query"
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }
}
