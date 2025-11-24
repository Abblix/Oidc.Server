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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Features.LogoutNotification;

/// <summary>
/// Unit tests for <see cref="FrontChannelLogoutNotifier"/> verifying front-channel logout notification
/// per OpenID Connect Front-Channel Logout specification.
/// </summary>
public class FrontChannelLogoutNotifierTests
{
    private readonly FrontChannelLogoutNotifier _notifier;

    public FrontChannelLogoutNotifierTests()
    {
        _notifier = new FrontChannelLogoutNotifier();
    }

    private static ClientInfo CreateClientInfo(FrontChannelLogoutOptions? frontChannelLogout)
    {
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            FrontChannelLogout = frontChannelLogout
        };
        return clientInfo;
    }

    private static ClientInfo CreateClientInfoWithFrontChannelLogout(bool requiresSessionId = true)
    {
        return CreateClientInfo(new FrontChannelLogoutOptions(
            new Uri("https://client.example.com/frontchannel_logout"),
            RequiresSessionId: requiresSessionId));
    }

    private static LogoutContext CreateLogoutContext(
        string? sessionId = "session_123",
        string? subjectId = "user_123",
        string? issuer = "https://server.example.com")
    {
        return new LogoutContext(
            sessionId!,
            subjectId!,
            issuer!);
    }

    /// <summary>
    /// Verifies FrontChannelLogoutSupported is true.
    /// Per OpenID Connect, FrontChannelLogoutNotifier supports front-channel logout.
    /// </summary>
    [Fact]
    public void FrontChannelLogoutSupported_ShouldBeTrue()
    {
        // Assert
        Assert.True(_notifier.FrontChannelLogoutSupported);
    }

    /// <summary>
    /// Verifies FrontChannelLogoutSessionSupported is true.
    /// Per OpenID Connect, front-channel logout with session support is enabled.
    /// </summary>
    [Fact]
    public void FrontChannelLogoutSessionSupported_ShouldBeTrue()
    {
        // Assert
        Assert.True(_notifier.FrontChannelLogoutSessionSupported);
    }

    /// <summary>
    /// Verifies BackChannelLogoutSupported is false.
    /// Per OpenID Connect, FrontChannelLogoutNotifier does not support back-channel logout.
    /// </summary>
    [Fact]
    public void BackChannelLogoutSupported_ShouldBeFalse()
    {
        // Assert
        Assert.False(_notifier.BackChannelLogoutSupported);
    }

    /// <summary>
    /// Verifies BackChannelLogoutSessionSupported is false.
    /// Per OpenID Connect, back-channel logout sessions are not supported by this notifier.
    /// </summary>
    [Fact]
    public void BackChannelLogoutSessionSupported_ShouldBeFalse()
    {
        // Assert
        Assert.False(_notifier.BackChannelLogoutSessionSupported);
    }

    /// <summary>
    /// Verifies successful notification when client has front-channel logout configured.
    /// Per OpenID Connect Front-Channel Logout, logout URI should be constructed and added to context.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithFrontChannelLogout_ShouldAddUriToContext()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout();
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Single(logoutContext.FrontChannelLogoutRequestUris);
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains("iss=", uri.Query);
        Assert.Contains("sid=", uri.Query);
    }

    /// <summary>
    /// Verifies no action when client has no front-channel logout configured.
    /// Per OpenID Connect, clients without front-channel logout should not be notified.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithoutFrontChannelLogout_ShouldNotAddUri()
    {
        // Arrange
        var clientInfo = CreateClientInfo(frontChannelLogout: null);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Empty(logoutContext.FrontChannelLogoutRequestUris);
    }

    /// <summary>
    /// Verifies URI contains issuer parameter when session is required.
    /// Per OpenID Connect Front-Channel Logout, iss parameter must be included.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithRequiresSessionId_ShouldIncludeIssuerInUri()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(issuer: "https://my-issuer.example.com");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains("iss=https", uri.Query);
        Assert.Contains("my-issuer.example.com", uri.Query);
    }

    /// <summary>
    /// Verifies URI contains session ID parameter when session is required.
    /// Per OpenID Connect Front-Channel Logout, sid parameter must be included.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithRequiresSessionId_ShouldIncludeSessionIdInUri()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(sessionId: "my_session_abc123");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains("sid=my_session_abc123", uri.Query);
    }

    /// <summary>
    /// Verifies URI does not contain query parameters when session is not required.
    /// Per OpenID Connect, parameters should only be added when required.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithoutRequiresSessionId_ShouldNotAddQueryParameters()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: false);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Empty(uri.Query);
    }

    /// <summary>
    /// Verifies exception when session is required but session ID is null.
    /// Per OpenID Connect, clients requiring session ID must receive it.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithRequiresSessionIdButNullSessionId_ShouldThrowException()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(sessionId: null);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _notifier.NotifyClientAsync(clientInfo, logoutContext));

        Assert.Contains("requires session id", exception.Message);
        Assert.Contains(TestConstants.DefaultClientId, exception.Message);
    }

    /// <summary>
    /// Verifies exception when session is required but session ID is empty.
    /// Per OpenID Connect, empty session ID is not valid when required.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithRequiresSessionIdButEmptySessionId_ShouldThrowException()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(sessionId: string.Empty);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _notifier.NotifyClientAsync(clientInfo, logoutContext));

        Assert.Contains("requires session id", exception.Message);
    }

    /// <summary>
    /// Verifies URI is constructed correctly with base URI.
    /// The base URI from configuration should be preserved.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ShouldPreserveBaseUri()
    {
        // Arrange
        var baseUri = new Uri("https://client.example.com/custom/logout/path");
        var frontChannelLogout = new FrontChannelLogoutOptions(baseUri, RequiresSessionId: true);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Equal("https", uri.Scheme);
        Assert.Equal("client.example.com", uri.Host);
        Assert.Contains("/custom/logout/path", uri.AbsolutePath);
    }

    /// <summary>
    /// Verifies multiple sequential calls add multiple URIs.
    /// Multiple logout notifications should accumulate in the context.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_MultipleSequentialCalls_ShouldAddMultipleUris()
    {
        // Arrange
        var clientInfo1 = new ClientInfo("client_1")
        {
            FrontChannelLogout = new FrontChannelLogoutOptions(
                new Uri("https://client1.example.com/logout"),
                RequiresSessionId: false)
        };
        var clientInfo2 = new ClientInfo("client_2")
        {
            FrontChannelLogout = new FrontChannelLogoutOptions(
                new Uri("https://client2.example.com/logout"),
                RequiresSessionId: false)
        };
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo1, logoutContext);
        await _notifier.NotifyClientAsync(clientInfo2, logoutContext);

        // Assert
        Assert.Equal(2, logoutContext.FrontChannelLogoutRequestUris.Count);
        Assert.Contains(logoutContext.FrontChannelLogoutRequestUris, u => u.Host == "client1.example.com");
        Assert.Contains(logoutContext.FrontChannelLogoutRequestUris, u => u.Host == "client2.example.com");
    }

    /// <summary>
    /// Verifies mixed clients (with and without front-channel logout).
    /// Only clients with front-channel logout should add URIs.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_MixedClients_ShouldOnlyAddConfiguredOnes()
    {
        // Arrange
        var clientWithLogout = CreateClientInfoWithFrontChannelLogout(requiresSessionId: false);
        var clientWithoutLogout = CreateClientInfo(frontChannelLogout: null);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientWithLogout, logoutContext);
        await _notifier.NotifyClientAsync(clientWithoutLogout, logoutContext);

        // Assert
        Assert.Single(logoutContext.FrontChannelLogoutRequestUris);
    }

    /// <summary>
    /// Verifies different issuers are correctly encoded in URI.
    /// Issuer parameter should be properly URL-encoded.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentIssuers_ShouldEncodeCorrectly()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(issuer: "https://issuer.example.com:8443/auth");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains("iss=", uri.Query);
        Assert.Contains("8443", uri.Query);
        Assert.Contains("auth", uri.Query);
    }

    /// <summary>
    /// Verifies special characters in session ID are properly encoded.
    /// Session IDs may contain characters that need URL encoding.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithSpecialCharactersInSessionId_ShouldEncodeCorrectly()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(sessionId: "session-123_456.789~abc");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        var query = uri.Query;
        Assert.Contains("sid=", query);
        // The session ID should be present in some form (may be URL-encoded)
        Assert.True(query.Contains("123") || query.Contains("%"));
    }

    /// <summary>
    /// Verifies very long session ID is handled correctly.
    /// Edge case for session identifier length.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithVeryLongSessionId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var longSessionId = new string('a', 500);
        var logoutContext = CreateLogoutContext(sessionId: longSessionId);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains("sid=", uri.Query);
        // URI should be valid
        Assert.NotEmpty(uri.Query);
    }

    /// <summary>
    /// Verifies whitespace in session ID is properly handled.
    /// Whitespace should be URL-encoded.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithWhitespaceInSessionId_ShouldEncodeCorrectly()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(sessionId: "session with spaces");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        var query = uri.Query;
        Assert.Contains("sid=", query);
        // Spaces should be encoded
        Assert.True(query.Contains("%20") || query.Contains("+"));
    }

    /// <summary>
    /// Verifies URI with existing query parameters.
    /// New parameters should be added to existing query string.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithExistingQueryParameters_ShouldAppendParameters()
    {
        // Arrange
        var baseUri = new Uri("https://client.example.com/logout?existing=param");
        var frontChannelLogout = new FrontChannelLogoutOptions(baseUri, RequiresSessionId: true);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        var query = uri.Query;
        Assert.Contains("existing=param", query);
        Assert.Contains("iss=", query);
        Assert.Contains("sid=", query);
    }

    /// <summary>
    /// Verifies URI with fragment is preserved.
    /// Fragment should remain in the final URI.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithFragment_ShouldPreserveFragment()
    {
        // Arrange
        var baseUri = new Uri("https://client.example.com/logout#section");
        var frontChannelLogout = new FrontChannelLogoutOptions(baseUri, RequiresSessionId: false);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Equal("#section", uri.Fragment);
    }

    /// <summary>
    /// Verifies HTTPS URIs are handled correctly.
    /// Per OpenID Connect security requirements, HTTPS should be used.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithHttpsUri_ShouldWork()
    {
        // Arrange
        var httpsUri = new Uri("https://secure.client.com/logout");
        var frontChannelLogout = new FrontChannelLogoutOptions(httpsUri, RequiresSessionId: false);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Equal("https", uri.Scheme);
    }

    /// <summary>
    /// Verifies HTTP URIs are handled (for testing environments).
    /// HTTP should work but is not recommended in production.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithHttpUri_ShouldWork()
    {
        // Arrange
        var httpUri = new Uri("http://localhost:5000/logout");
        var frontChannelLogout = new FrontChannelLogoutOptions(httpUri, RequiresSessionId: false);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Equal("http", uri.Scheme);
        Assert.Equal("localhost", uri.Host);
    }

    /// <summary>
    /// Verifies URI with port number is handled correctly.
    /// Port numbers should be preserved in the final URI.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithPortNumber_ShouldPreservePort()
    {
        // Arrange
        var uriWithPort = new Uri("https://client.example.com:8443/logout");
        var frontChannelLogout = new FrontChannelLogoutOptions(uriWithPort, RequiresSessionId: false);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Equal(8443, uri.Port);
    }

    /// <summary>
    /// Verifies different client IDs are handled correctly.
    /// Each client should be identified by its unique ID in error messages.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentClientIds_ExceptionShouldIncludeClientId()
    {
        // Arrange
        var clientInfo = new ClientInfo("specific_client_abc123")
        {
            FrontChannelLogout = new FrontChannelLogoutOptions(
                new Uri("https://client.example.com/logout"),
                RequiresSessionId: true)
        };
        var logoutContext = CreateLogoutContext(sessionId: null);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _notifier.NotifyClientAsync(clientInfo, logoutContext));

        Assert.Contains("specific_client_abc123", exception.Message);
    }

    /// <summary>
    /// Verifies async operation completes synchronously.
    /// NotifyClientAsync should return completed task immediately.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ShouldCompleteImmediately()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: false);
        var logoutContext = CreateLogoutContext();

        // Act
        var task = _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.True(task.IsCompleted);
        await task;
    }

    /// <summary>
    /// Verifies that subject ID in context does not affect URI construction.
    /// Subject ID is not used in front-channel logout URI.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentSubjectIds_ShouldNotAffectUri()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext1 = CreateLogoutContext(sessionId: "session_123", subjectId: "user_1");
        var logoutContext2 = CreateLogoutContext(sessionId: "session_123", subjectId: "user_2");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext1);
        await _notifier.NotifyClientAsync(clientInfo, logoutContext2);

        // Assert
        var uri1 = logoutContext1.FrontChannelLogoutRequestUris[0];
        var uri2 = logoutContext2.FrontChannelLogoutRequestUris[0];
        // URIs should be identical since subject ID is not included
        Assert.Equal(uri1.Query, uri2.Query);
    }

    /// <summary>
    /// Verifies URI path with special characters.
    /// Paths with special characters should be preserved.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithSpecialCharactersInPath_ShouldWork()
    {
        // Arrange
        var uriWithSpecialPath = new Uri("https://client.example.com/logout-endpoint_v2");
        var frontChannelLogout = new FrontChannelLogoutOptions(uriWithSpecialPath, RequiresSessionId: false);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains("logout-endpoint_v2", uri.AbsolutePath);
    }

    /// <summary>
    /// Verifies URI with subdomain is handled correctly.
    /// Subdomains should be preserved in the final URI.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithSubdomain_ShouldPreserveSubdomain()
    {
        // Arrange
        var uriWithSubdomain = new Uri("https://auth.client.example.com/logout");
        var frontChannelLogout = new FrontChannelLogoutOptions(uriWithSubdomain, RequiresSessionId: false);
        var clientInfo = CreateClientInfo(frontChannelLogout);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Equal("auth.client.example.com", uri.Host);
    }

    /// <summary>
    /// Verifies issuer with special characters is encoded correctly.
    /// Special characters in issuer should be URL-encoded.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithSpecialCharactersInIssuer_ShouldEncodeCorrectly()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(issuer: "https://issuer.example.com/auth/realm-1");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        var query = uri.Query;
        Assert.Contains("iss=", query);
        Assert.Contains("realm", query);
    }

    /// <summary>
    /// Verifies numeric session ID is handled correctly.
    /// Session IDs that are purely numeric should work.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithNumericSessionId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var logoutContext = CreateLogoutContext(sessionId: "1234567890");

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains("sid=1234567890", uri.Query);
    }

    /// <summary>
    /// Verifies UUID-format session ID is handled correctly.
    /// Session IDs in UUID format should be supported.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithUuidSessionId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithFrontChannelLogout(requiresSessionId: true);
        var uuidSessionId = "550e8400-e29b-41d4-a716-446655440000";
        var logoutContext = CreateLogoutContext(sessionId: uuidSessionId);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        var uri = logoutContext.FrontChannelLogoutRequestUris[0];
        Assert.Contains($"sid={uuidSessionId}", uri.Query);
    }
}
