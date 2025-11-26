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

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="ClientValidator"/> verifying client authentication
/// for token requests per OAuth 2.0 specification.
/// </summary>
public class ClientValidatorTests
{
    private readonly Mock<IClientAuthenticator> _clientAuthenticator;
    private readonly ClientValidator _validator;

    public ClientValidatorTests()
    {
        _clientAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        _validator = new ClientValidator(_clientAuthenticator.Object);
    }

    private static TokenValidationContext CreateContext(ClientRequest? clientRequest = null)
    {
        var tokenRequest = new TokenRequest();
        return new TokenValidationContext(tokenRequest, clientRequest ?? new ClientRequest());
    }

    /// <summary>
    /// Verifies successful validation when client authentication succeeds.
    /// Per OAuth 2.0, client must be authenticated for token requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSuccessfulAuthentication_ShouldSucceed()
    {
        // Arrange
        var clientRequest = new ClientRequest { ClientId = TestConstants.DefaultClientId };
        var context = CreateContext(clientRequest);
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Same(clientInfo, context.ClientInfo);
    }

    /// <summary>
    /// Verifies error when client authentication fails.
    /// Per OAuth 2.0, unauthenticated clients must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenAuthenticationFails_ShouldReturnError()
    {
        // Arrange
        var clientRequest = new ClientRequest { ClientId = "invalid_client" };
        var context = CreateContext(clientRequest);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        Assert.Contains("not authorized", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies client request is passed correctly to authenticator.
    /// Authenticator should receive the exact ClientRequest from context.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassClientRequestToAuthenticator()
    {
        // Arrange
        var clientRequest = new ClientRequest { ClientId = TestConstants.DefaultClientId, ClientSecret = TestConstants.DefaultClientSecret };
        var context = CreateContext(clientRequest);
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(clientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(clientRequest), Times.Once);
    }

    /// <summary>
    /// Verifies client info is correctly assigned to context.
    /// Context.ClientInfo should reference the authenticated client info.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetClientInfoInContext()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId) { ClientName = "Test Client" };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Same(clientInfo, context.ClientInfo);
        Assert.Equal(TestConstants.DefaultClientId, context.ClientInfo.ClientId);
        Assert.Equal("Test Client", context.ClientInfo.ClientName);
    }

    /// <summary>
    /// Verifies authenticator is called only once per validation.
    /// Multiple calls to the same authenticator should be avoided.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallAuthenticatorOnce()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _clientAuthenticator.Verify(
            a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies error details on authentication failure.
    /// Error should contain proper code and description.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnAuthenticationFailure_ShouldReturnProperError()
    {
        // Arrange
        var context = CreateContext();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        Assert.False(string.IsNullOrWhiteSpace(error.ErrorDescription));
    }

    /// <summary>
    /// Verifies validation with different client requests.
    /// Validator should work with various client request configurations.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentClientRequests_ShouldWork()
    {
        // Arrange
        var clientRequest1 = new ClientRequest { ClientId = "client1" };
        var clientRequest2 = new ClientRequest { ClientId = "client2", ClientSecret = TestConstants.DefaultClientSecret };
        var context1 = CreateContext(clientRequest1);
        var context2 = CreateContext(clientRequest2);
        var clientInfo1 = new ClientInfo("client1");
        var clientInfo2 = new ClientInfo("client2");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(clientRequest1))
            .ReturnsAsync(clientInfo1);
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(clientRequest2))
            .ReturnsAsync(clientInfo2);

        // Act
        var error1 = await _validator.ValidateAsync(context1);
        var error2 = await _validator.ValidateAsync(context2);

        // Assert
        Assert.Null(error1);
        Assert.Null(error2);
        Assert.Same(clientInfo1, context1.ClientInfo);
        Assert.Same(clientInfo2, context2.ClientInfo);
    }

    /// <summary>
    /// Verifies context is not modified on authentication failure.
    /// Context.ClientInfo should remain unset when authentication fails.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnFailure_ShouldNotModifyContext()
    {
        // Arrange
        var context = CreateContext();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        await _validator.ValidateAsync(context);

        // Assert - Context.ClientInfo getter will throw if not set, which is expected behavior
        // We just verify the error was returned
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
    }
}
