// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
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
        return new (TestConstants.DefaultClientId)
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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("not valid", error.ErrorDescription);
    }

    /// <summary>
    /// A redirect address with no client named has nothing confirming it, so OpenID Connect RP-Initiated Logout 1.0
    /// section 3 rules the redirect out; the logout goes on, without the address and the state that goes back to it.
    /// </summary>
    [Fact]
    public async Task ARedirectWithNoClientNamed_IsDroppedAndTheLogoutGoesOn()
    {
        var context = CreateContext(new Uri("https://client.example.com/logout"), clientInfo: null);
        context.Request = context.Request with { State = "af0ifjsldkj" };

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(error);
        Assert.Null(context.Request.PostLogoutRedirectUri);
        Assert.Null(context.Request.State);
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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert - Should succeed because scheme and host are case-insensitive
        Assert.Null(error);
    }

    /// <summary>
    /// A post-logout redirect URI carrying a fragment or user information the registered one lacks is refused, since
    /// the comparison is exact and takes both into account.
    /// </summary>
    [Theory]
    [InlineData("https://client.example.com/logout#fragment")]
    [InlineData("https://user@client.example.com/logout")]
    public async Task ValidateAsync_WithFragmentOrUserInfo_ShouldReturnError(string requested)
    {
        var redirectUri = new Uri(requested);
        var clientInfo = CreateClientInfo("https://client.example.com/logout");
        var context = CreateContext(redirectUri, clientInfo);

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }
}
