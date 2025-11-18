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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// Unit tests for <see cref="PostLogoutRedirectUrisValidator"/> verifying post-logout redirect URI
/// validation per OIDC Session Management specification.
/// </summary>
public class PostLogoutRedirectUrisValidatorTests
{
    private readonly PostLogoutRedirectUrisValidator _validator;

    public PostLogoutRedirectUrisValidatorTests()
    {
        var logger = new Mock<ILogger<PostLogoutRedirectUrisValidator>>();
        _validator = new PostLogoutRedirectUrisValidator(logger.Object);
    }

    private static EndSessionValidationContext CreateContext(
        Uri? postLogoutRedirectUri = null,
        ClientInfo? clientInfo = null)
    {
        var request = new EndSessionRequest
        {
            PostLogoutRedirectUri = postLogoutRedirectUri,
        };
        var context = new EndSessionValidationContext(request);
        if (clientInfo != null)
        {
            context.ClientInfo = clientInfo;
        }
        return context;
    }

    private static ClientInfo CreateClientInfo(params string[] postLogoutRedirectUris)
    {
        return new ("client_123")
        {
            PostLogoutRedirectUris = postLogoutRedirectUris.Select(uri => new Uri(uri)).ToArray(),
        };
    }

    /// <summary>
    /// Verifies successful validation when no post-logout redirect URI provided.
    /// Per OIDC Session Management, post-logout redirect URI is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutRedirectUri_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(postLogoutRedirectUri: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies successful validation with valid post-logout redirect URI.
    /// URI must be registered for the client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidRedirectUri_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout");
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies error when redirect URI is not registered for client.
    /// Per OIDC, only pre-registered URIs are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnregisteredRedirectUri_ShouldReturnError()
    {
        // Arrange
        var redirectUri = new Uri("https://unregistered.example.com/logout");
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("not valid", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when redirect URI provided but no client info available.
    /// Client info is required to validate redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithRedirectUriButNoClientInfo_ShouldReturnError()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
        Assert.Contains("Unable to determine a client", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies redirect URI matching is exact.
    /// Per OAuth 2.0, redirect URI matching must be exact.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExactMatchRequired_ShouldValidateExactly()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout?param=value");
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert - Should fail because query parameter doesn't match
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Verifies successful validation with multiple registered URIs.
    /// Client can have multiple post-logout redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleRegisteredUris_ShouldMatchAny()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout2");
        var clientInfo = CreateClientInfo(
            "https://client.example.com/logout1",
            "https://client.example.com/logout2",
            "https://client.example.com/logout3");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies URI comparison is case-sensitive for path.
    /// Per RFC 3986, URI scheme and host are case-insensitive, but path is case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldBeCaseSensitiveForPath()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/Logout");
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert - Should fail due to case mismatch in path
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Verifies URI comparison is case-insensitive for scheme and host.
    /// Per RFC 3986, URI scheme and host are case-insensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldBeCaseInsensitiveForSchemeAndHost()
    {
        // Arrange
        var redirectUri = new Uri("HTTPS://CLIENT.EXAMPLE.COM/logout");
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert - Should succeed because scheme and host are case-insensitive
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies validation with fragment in URI.
    /// Per RFC 3986, fragments are stripped by Uri class before comparison.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFragment_ShouldIgnoreFragment()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout#fragment");
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert - Fragment is ignored by Uri, so validation succeeds
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies validation with trailing slash.
    /// Per OAuth 2.0, trailing slash makes a difference.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTrailingSlash_ShouldNotMatch()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout/");
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Verifies empty registered URIs list.
    /// If client has no registered post-logout redirect URIs, any URI should be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyRegisteredUris_ShouldReturnError()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout");
        var clientInfo = CreateClientInfo(); // No URIs registered
        var context = CreateContext(redirectUri, clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }
}
