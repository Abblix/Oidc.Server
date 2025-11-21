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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="ClientValidator"/> verifying CIBA client authentication
/// and authorization per OpenID Connect CIBA specification.
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

    private BackChannelAuthenticationValidationContext CreateContext()
    {
        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid", "profile"],
        };

        var clientRequest = new ClientRequest
        {
            ClientId = "test-client",
        };

        return new BackChannelAuthenticationValidationContext(request, clientRequest);
    }

    /// <summary>
    /// Verifies successful validation when client is authenticated and authorized for CIBA.
    /// Per CIBA specification, client must be authenticated and grant CIBA permission.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidCibaClient_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = [GrantTypes.Ciba],
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Same(clientInfo, context.ClientInfo);
    }

    /// <summary>
    /// Verifies validation succeeds when client has multiple grant types including CIBA.
    /// Clients can support multiple authentication flows simultaneously.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleGrantTypesIncludingCiba_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.Ciba, GrantTypes.RefreshToken],
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when client authentication fails.
    /// Per CIBA specification, unauthenticated clients must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnauthenticatedClient_ShouldReturnUnauthorizedClient()
    {
        // Arrange
        var context = CreateContext();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Equal("The client is not authorized", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when client doesn't support CIBA grant type.
    /// Per CIBA specification, only clients explicitly configured for CIBA can use it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutCibaGrantType_ShouldReturnUnauthorizedClient()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken]
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Equal("The Client is not authorized to use this authentication flow", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when client has empty grant types array.
    /// Clients with no configured grant types cannot authenticate.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyGrantTypes_ShouldReturnUnauthorizedClient()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = []
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }

    /// <summary>
    /// Verifies ClientInfo is set on context upon successful validation.
    /// Per validation pattern, context must be populated for downstream validators.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetClientInfoOnContext()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = [GrantTypes.Ciba],
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
            ClientName = "Test Client"
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Same(clientInfo, context.ClientInfo);
        Assert.Equal("Test Client", context.ClientInfo.ClientName);
    }

    /// <summary>
    /// Verifies client authenticator is called with correct client request.
    /// Ensures proper delegation to authentication service.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallClientAuthenticatorWithCorrectRequest()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = [GrantTypes.Ciba],
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll
        };

        ClientRequest? capturedRequest = null;
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Callback<ClientRequest>(r => capturedRequest = r)
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(capturedRequest);
        Assert.Same(context.ClientRequest, capturedRequest);
    }

    /// <summary>
    /// Verifies validation with confidential client credentials.
    /// CIBA typically requires confidential clients for security.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithConfidentialClient_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext();
        context.ClientRequest.ClientSecret = "secret123";

        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = [GrantTypes.Ciba],
            BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
            ClientType = ClientType.Confidential
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies case-sensitive grant type matching.
    /// Grant type comparison must be exact per OIDC specification.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIncorrectCaseGrantType_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo("test-client")
        {
            AllowedGrantTypes = ["urn:openid:params:grant-type:CIBA"] // Wrong case
        };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(context.ClientRequest))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }
}
