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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationRequestValidator"/> verifying
/// main validation workflow per OpenID Connect CIBA specification.
/// </summary>
public class BackChannelAuthenticationRequestValidatorTests
{
    private readonly Mock<IBackChannelAuthenticationContextValidator> _contextValidator;
    private readonly BackChannelAuthenticationRequestValidator _validator;

    public BackChannelAuthenticationRequestValidatorTests()
    {
        _contextValidator = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        _validator = new BackChannelAuthenticationRequestValidator(_contextValidator.Object);
    }

    /// <summary>
    /// Verifies successful validation returns ValidBackChannelAuthenticationRequest.
    /// Per CIBA specification, valid requests must proceed to processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidRequest_ShouldReturnValidRequest()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"],
            LoginHint = "user@example.com"
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromMinutes(5);
                ctx.Scope = [new ScopeDefinition("openid", Array.Empty<string>())];
                ctx.Resources = [];
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest);
        Assert.Same(request, validRequest.Model);
        Assert.Equal("test-client", validRequest.ClientInfo.ClientId);
        Assert.Equal(TimeSpan.FromMinutes(5), validRequest.ExpiresIn);
        Assert.Single(validRequest.Scope);
        Assert.Empty(validRequest.Resources);
    }

    /// <summary>
    /// Verifies validation error is returned when context validator fails.
    /// Per CIBA specification, validation errors must prevent request processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithContextValidatorError_ShouldReturnError()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"]
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        var error = new OidcError(ErrorCodes.InvalidRequest, "No identity hint provided");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync(error);

        // Act
        var result = await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var actualError));
        Assert.Same(error, actualError);
    }

    /// <summary>
    /// Verifies context validator is called with correct context.
    /// Context must contain original request and client request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallContextValidatorWithCorrectContext()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid", "profile"],
            LoginHint = "user@example.com",
            BindingMessage = "Test message"
        };

        var clientRequest = new ClientRequest
        {
            ClientId = "test-client",
            ClientSecret = "secret"
        };

        BackChannelAuthenticationValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                capturedContext = ctx;
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromMinutes(5);
                ctx.Scope = [];
                ctx.Resources = [];
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Same(request, capturedContext.Request);
        Assert.Same(clientRequest, capturedContext.ClientRequest);
        Assert.Equal("test-client", capturedContext.ClientRequest.ClientId);
        Assert.Equal("secret", capturedContext.ClientRequest.ClientSecret);
    }

    /// <summary>
    /// Verifies ValidBackChannelAuthenticationRequest includes LoginHintToken when provided.
    /// Per CIBA specification, login_hint_token must be preserved for processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLoginHintToken_ShouldIncludeInValidRequest()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"],
            LoginHintToken = "jwt-token"
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        var loginHintToken = new Abblix.Jwt.JsonWebToken();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromMinutes(5);
                ctx.LoginHintToken = loginHintToken;
                ctx.Scope = [];
                ctx.Resources = [];
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest.LoginHintToken);
        Assert.Same(loginHintToken, validRequest.LoginHintToken);
    }

    /// <summary>
    /// Verifies ValidBackChannelAuthenticationRequest includes IdToken when provided.
    /// Per CIBA specification, id_token_hint must be preserved for user identification.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIdTokenHint_ShouldIncludeInValidRequest()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"],
            IdTokenHint = "id-token"
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        var idToken = new Abblix.Jwt.JsonWebToken();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromMinutes(5);
                ctx.IdToken = idToken;
                ctx.Scope = [];
                ctx.Resources = [];
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest.IdToken);
        Assert.Same(idToken, validRequest.IdToken);
    }

    /// <summary>
    /// Verifies ValidBackChannelAuthenticationRequest includes multiple scopes.
    /// Per OIDC Core, clients may request multiple scopes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleScopes_ShouldIncludeAllInValidRequest()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid", "profile", "email"],
            LoginHint = "user@example.com"
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        var scopeDefinitions = new[]
        {
            new ScopeDefinition("openid", Array.Empty<string>()),
            new ScopeDefinition("profile", new[] { "name", "given_name", "family_name" }),
            new ScopeDefinition("email", new[] { "email", "email_verified" })
        };

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromMinutes(5);
                ctx.Scope = scopeDefinitions;
                ctx.Resources = [];
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(3, validRequest.Scope.Length);
        Assert.Equal("openid", validRequest.Scope[0].Scope);
        Assert.Equal("profile", validRequest.Scope[1].Scope);
        Assert.Equal("email", validRequest.Scope[2].Scope);
    }

    /// <summary>
    /// Verifies ValidBackChannelAuthenticationRequest includes multiple resources.
    /// Per RFC 8707, multiple resource indicators may be specified.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleResources_ShouldIncludeAllInValidRequest()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"],
            LoginHint = "user@example.com",
            Resources = [new Uri("https://api1.example.com"), new Uri("https://api2.example.com")]
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        var resourceDefinitions = new[]
        {
            new ResourceDefinition(new Uri("https://api1.example.com"), new ScopeDefinition("openid", Array.Empty<string>())),
            new ResourceDefinition(new Uri("https://api2.example.com"), new ScopeDefinition("openid", Array.Empty<string>()))
        };

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromMinutes(5);
                ctx.Scope = [];
                ctx.Resources = resourceDefinitions;
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(2, validRequest.Resources.Length);
        Assert.Equal(new Uri("https://api1.example.com"), validRequest.Resources[0].Resource);
        Assert.Equal(new Uri("https://api2.example.com"), validRequest.Resources[1].Resource);
    }

    /// <summary>
    /// Verifies ValidBackChannelAuthenticationRequest includes custom expiry.
    /// Per CIBA specification, requested_expiry should be respected if valid.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomExpiry_ShouldIncludeInValidRequest()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"],
            LoginHint = "user@example.com",
            RequestedExpiry = TimeSpan.FromSeconds(300) // 5 minutes
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromSeconds(300);
                ctx.Scope = [];
                ctx.Resources = [];
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(request, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Equal(TimeSpan.FromSeconds(300), validRequest.ExpiresIn);
    }

    /// <summary>
    /// Verifies context validator is called only once per validation.
    /// Multiple calls to context validator would indicate logic error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallContextValidatorOnce()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"],
            LoginHint = "user@example.com"
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("test-client");
                ctx.ExpiresIn = TimeSpan.FromMinutes(5);
                ctx.Scope = [];
                ctx.Resources = [];
            }))
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(request, clientRequest);

        // Assert
        _contextValidator.Verify(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies different error codes are properly propagated.
    /// All CIBA-specific error codes must be returned correctly.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentErrorCodes_ShouldPropagateCorrectly()
    {
        // Arrange
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"]
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        var testCases = new[]
        {
            ErrorCodes.InvalidRequest,
            ErrorCodes.InvalidScope,
            ErrorCodes.UnauthorizedClient,
            ErrorCodes.MissingUserCode,
            ErrorCodes.InvalidTarget
        };

        foreach (var errorCode in testCases)
        {
            var error = new OidcError(errorCode, $"Error: {errorCode}");

            _contextValidator
                .Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
                .ReturnsAsync(error);

            // Act
            var result = await _validator.ValidateAsync(request, clientRequest);

            // Assert
            Assert.True(result.TryGetFailure(out var actualError));
            Assert.Equal(errorCode, actualError.Error);
            Assert.Equal($"Error: {errorCode}", actualError.ErrorDescription);

            _contextValidator.Reset();
        }
    }
}
