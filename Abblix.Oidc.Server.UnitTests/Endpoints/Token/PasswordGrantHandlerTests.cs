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
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="PasswordGrantHandler"/> verifying the Resource Owner Password Credentials grant type
/// as defined in RFC 6749 section 4.3.
/// Tests cover credential validation, parameter checks, and error conditions.
/// </summary>
public class PasswordGrantHandlerTests
{
    private const string ClientId = "test_client_123";
    private const string UserName = "testuser";
    private const string Password = "testpassword123";

    private readonly Mock<IParameterValidator> _parameterValidator;
    private readonly Mock<IUserCredentialsAuthenticator> _credentialsAuthenticator;
    private readonly PasswordGrantHandler _handler;

    public PasswordGrantHandlerTests()
    {
        _parameterValidator = new Mock<IParameterValidator>(MockBehavior.Strict);
        _credentialsAuthenticator = new Mock<IUserCredentialsAuthenticator>(MockBehavior.Strict);

        _handler = new PasswordGrantHandler(
            _parameterValidator.Object,
            _credentialsAuthenticator.Object);
    }

    /// <summary>
    /// Verifies that valid username and password credentials successfully authenticate the user
    /// and return an authorized grant.
    /// This is the standard Resource Owner Password Credentials flow.
    /// </summary>
    [Fact]
    public async Task ValidCredentials_ShouldReturnGrant()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest
        {
            UserName = UserName,
            Password = Password,
            Scope = [Scopes.OpenId]
        };

        _parameterValidator.Setup(v => v.Required(tokenRequest.UserName, nameof(tokenRequest.UserName)));
        _parameterValidator.Setup(v => v.Required(tokenRequest.Password, nameof(tokenRequest.Password)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession("user123", "session1", DateTimeOffset.UtcNow, "192.168.1.1"),
            Context: new AuthorizationContext(ClientId, tokenRequest.Scope, null));

        _credentialsAuthenticator
            .Setup(a => a.ValidateAsync(UserName, Password, It.Is<AuthorizationContext>(ctx =>
                ctx.ClientId == ClientId &&
                ctx.Scope.SequenceEqual(tokenRequest.Scope))))
            .ReturnsAsync(expectedGrant);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(ClientId, grant.Context.ClientId);
    }

    /// <summary>
    /// Verifies that when credentials are invalid, the authenticator's error is properly propagated.
    /// </summary>
    [Fact]
    public async Task InvalidCredentials_ShouldReturnError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest
        {
            UserName = UserName,
            Password = "wrongpassword",
            Scope = [Scopes.OpenId]
        };

        _parameterValidator.Setup(v => v.Required(tokenRequest.UserName, nameof(tokenRequest.UserName)));
        _parameterValidator.Setup(v => v.Required(tokenRequest.Password, nameof(tokenRequest.Password)));

        var authError = new OidcError(ErrorCodes.InvalidGrant, "Invalid username or password");
        _credentialsAuthenticator
            .Setup(a => a.ValidateAsync(UserName, "wrongpassword", It.IsAny<AuthorizationContext>()))
            .ReturnsAsync(authError);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("Invalid username or password", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that when the user account is locked, the authenticator's error is properly returned.
    /// </summary>
    [Fact]
    public async Task LockedAccount_ShouldReturnError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest
        {
            UserName = UserName,
            Password = Password,
            Scope = [Scopes.OpenId]
        };

        _parameterValidator.Setup(v => v.Required(tokenRequest.UserName, nameof(tokenRequest.UserName)));
        _parameterValidator.Setup(v => v.Required(tokenRequest.Password, nameof(tokenRequest.Password)));

        var authError = new OidcError(ErrorCodes.InvalidGrant, "Account is locked");
        _credentialsAuthenticator
            .Setup(a => a.ValidateAsync(UserName, Password, It.IsAny<AuthorizationContext>()))
            .ReturnsAsync(authError);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("Account is locked", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that a request with special characters in username and password is processed correctly.
    /// </summary>
    [Fact]
    public async Task SpecialCharactersInCredentials_ShouldProcess()
    {
        // Arrange
        var specialUserName = "user@example.com";
        var specialPassword = "p@ss:w0rd!#$%^&*()";
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest
        {
            UserName = specialUserName,
            Password = specialPassword,
            Scope = [Scopes.OpenId]
        };

        _parameterValidator.Setup(v => v.Required(tokenRequest.UserName, nameof(tokenRequest.UserName)));
        _parameterValidator.Setup(v => v.Required(tokenRequest.Password, nameof(tokenRequest.Password)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession("user123", "session1", DateTimeOffset.UtcNow, "192.168.1.1"),
            Context: new AuthorizationContext(ClientId, tokenRequest.Scope, null));

        _credentialsAuthenticator
            .Setup(a => a.ValidateAsync(specialUserName, specialPassword, It.IsAny<AuthorizationContext>()))
            .ReturnsAsync(expectedGrant);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
    }

    /// <summary>
    /// Verifies that a request with multiple scopes is processed correctly.
    /// </summary>
    [Fact]
    public async Task MultipleScopes_ShouldPassToAuthenticator()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };
        var tokenRequest = new TokenRequest
        {
            UserName = UserName,
            Password = Password,
            Scope = scopes
        };

        _parameterValidator.Setup(v => v.Required(tokenRequest.UserName, nameof(tokenRequest.UserName)));
        _parameterValidator.Setup(v => v.Required(tokenRequest.Password, nameof(tokenRequest.Password)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession("user123", "session1", DateTimeOffset.UtcNow, "192.168.1.1"),
            Context: new AuthorizationContext(ClientId, scopes, null));

        _credentialsAuthenticator
            .Setup(a => a.ValidateAsync(UserName, Password, It.Is<AuthorizationContext>(ctx =>
                ctx.Scope.SequenceEqual(scopes))))
            .ReturnsAsync(expectedGrant);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
    }

    /// <summary>
    /// Verifies that a request with no scopes specified is processed correctly.
    /// </summary>
    [Fact]
    public async Task NoScopes_ShouldPassNullToAuthenticator()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest
        {
            UserName = UserName,
            Password = Password,
            Scope = null
        };

        _parameterValidator.Setup(v => v.Required(tokenRequest.UserName, nameof(tokenRequest.UserName)));
        _parameterValidator.Setup(v => v.Required(tokenRequest.Password, nameof(tokenRequest.Password)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession("user123", "session1", DateTimeOffset.UtcNow, "192.168.1.1"),
            Context: new AuthorizationContext(ClientId, null, null));

        _credentialsAuthenticator
            .Setup(a => a.ValidateAsync(UserName, Password, It.Is<AuthorizationContext>(ctx =>
                ctx.Scope == null)))
            .ReturnsAsync(expectedGrant);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
    }

    /// <summary>
    /// Verifies that the handler reports the correct supported grant type.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldReturnPassword()
    {
        // Act
        var grantTypes = _handler.GrantTypesSupported.ToArray();

        // Assert
        Assert.Single(grantTypes);
        Assert.Equal(GrantTypes.Password, grantTypes[0]);
    }

    /// <summary>
    /// Verifies that the context passed to the authenticator contains the correct client ID.
    /// </summary>
    [Fact]
    public async Task AuthorizationContext_ShouldContainClientId()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest
        {
            UserName = UserName,
            Password = Password,
            Scope = [Scopes.OpenId]
        };

        _parameterValidator.Setup(v => v.Required(tokenRequest.UserName, nameof(tokenRequest.UserName)));
        _parameterValidator.Setup(v => v.Required(tokenRequest.Password, nameof(tokenRequest.Password)));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession("user123", "session1", DateTimeOffset.UtcNow, "192.168.1.1"),
            Context: new AuthorizationContext(ClientId, tokenRequest.Scope, null));

        AuthorizationContext capturedContext = null;
        _credentialsAuthenticator
            .Setup(a => a.ValidateAsync(UserName, Password, It.IsAny<AuthorizationContext>()))
            .ReturnsAsync(expectedGrant)
            .Callback<string, string, AuthorizationContext>((_, _, ctx) => capturedContext = ctx);

        // Act
        await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Equal(ClientId, capturedContext.ClientId);
        Assert.Equal(tokenRequest.Scope, capturedContext.Scope);
    }
}
