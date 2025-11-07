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
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using static System.Web.HttpUtility;
using static Abblix.Utils.HttpServerUtility;

namespace Abblix.Oidc.Server.UnitTests.Features.SessionManagement;

/// <summary>
/// Unit tests for <see cref="SessionManagementService"/> verifying OpenID Connect session management
/// as defined in OpenID Connect Session Management 1.0 specification.
/// Tests cover session cookie creation, session state generation, and check session endpoint response.
/// </summary>
public class SessionManagementServiceTests
{
    private const string CookieName = "TestSessionCookie";
    private const string CookieDomain = "example.com";
    private const string SameSiteValue = "None";
    private const string ClientId = "client_123";
    private const string SessionId = "session_abc456";
    private const string PathBase = "/auth";
    private const string RedirectUriString = "https://client.example.com/callback";

    private readonly Mock<IOptionsSnapshot<OidcOptions>> _optionsSnapshot;
    private readonly Mock<IRequestInfoProvider> _requestInfoProvider;
    private readonly OidcOptions _oidcOptions;

    public SessionManagementServiceTests()
    {
        _oidcOptions = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.CheckSession,
            CheckSessionCookie = new CheckSessionCookieOptions
            {
                Name = CookieName,
                Domain = CookieDomain,
                SameSite = SameSiteValue
            }
        };

        _optionsSnapshot = new Mock<IOptionsSnapshot<OidcOptions>>(MockBehavior.Strict);
        _optionsSnapshot.Setup(o => o.Value).Returns(_oidcOptions);

        _requestInfoProvider = new Mock<IRequestInfoProvider>(MockBehavior.Strict);
    }

    #region Enabled Property Tests

    /// <summary>
    /// Verifies that Enabled returns true when CheckSession endpoint is enabled.
    /// This is required per OIDC Session Management spec to indicate session management support.
    /// </summary>
    [Fact]
    public void Enabled_WhenCheckSessionEndpointEnabled_ReturnsTrue()
    {
        // Arrange
        _oidcOptions.EnabledEndpoints = OidcEndpoints.CheckSession;
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var result = service.Enabled;

        // Assert
        Assert.True(result);
    }

    /// <summary>
    /// Verifies that Enabled returns false when CheckSession endpoint is not enabled.
    /// This indicates session management is disabled for the OIDC provider.
    /// </summary>
    [Fact]
    public void Enabled_WhenCheckSessionEndpointNotEnabled_ReturnsFalse()
    {
        // Arrange
        _oidcOptions.EnabledEndpoints = OidcEndpoints.Token | OidcEndpoints.Authorize;
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var result = service.Enabled;

        // Assert
        Assert.False(result);
    }

    /// <summary>
    /// Verifies that Enabled returns true when CheckSession is among multiple enabled endpoints.
    /// This tests the flags enum HasFlag behavior with multiple endpoints enabled.
    /// </summary>
    [Fact]
    public void Enabled_WhenMultipleEndpointsIncludingCheckSession_ReturnsTrue()
    {
        // Arrange
        _oidcOptions.EnabledEndpoints = OidcEndpoints.Authorize | OidcEndpoints.Token | OidcEndpoints.CheckSession | OidcEndpoints.UserInfo;
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var result = service.Enabled;

        // Assert
        Assert.True(result);
    }

    /// <summary>
    /// Verifies that Enabled returns false when no endpoints are enabled.
    /// This tests the edge case of a completely disabled OIDC provider.
    /// </summary>
    [Fact]
    public void Enabled_WhenNoEndpointsEnabled_ReturnsFalse()
    {
        // Arrange
        _oidcOptions.EnabledEndpoints = 0;
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var result = service.Enabled;

        // Assert
        Assert.False(result);
    }

    #endregion

    #region GetSessionCookie Tests

    /// <summary>
    /// Verifies that GetSessionCookie returns a cookie with the name configured in options.
    /// Cookie name must match configuration for proper session tracking.
    /// </summary>
    [Fact]
    public void GetSessionCookie_ReturnsCookieWithCorrectName()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.Equal(CookieName, cookie.Name);
    }

    /// <summary>
    /// Verifies that GetSessionCookie sets HttpOnly to false.
    /// HttpOnly must be false to allow JavaScript access for session state monitoring per OIDC spec.
    /// </summary>
    [Fact]
    public void GetSessionCookie_SetsHttpOnlyToFalse()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.False(cookie.Options.HttpOnly);
    }

    /// <summary>
    /// Verifies that GetSessionCookie sets IsEssential to true.
    /// Session cookies are essential for authentication and must not be blocked by consent requirements.
    /// </summary>
    [Fact]
    public void GetSessionCookie_SetsIsEssentialToTrue()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.True(cookie.Options.IsEssential);
    }

    /// <summary>
    /// Verifies that GetSessionCookie sets Secure to true when request is HTTPS.
    /// Secure flag prevents cookie transmission over insecure channels.
    /// </summary>
    [Fact]
    public void GetSessionCookie_WhenHttps_SetsSecureToTrue()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.True(cookie.Options.Secure);
        _requestInfoProvider.Verify(r => r.IsHttps, Times.Once);
    }

    /// <summary>
    /// Verifies that GetSessionCookie sets Secure to false when request is HTTP.
    /// This allows development scenarios without HTTPS.
    /// </summary>
    [Fact]
    public void GetSessionCookie_WhenHttp_SetsSecureToFalse()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(false);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.False(cookie.Options.Secure);
        _requestInfoProvider.Verify(r => r.IsHttps, Times.Once);
    }

    /// <summary>
    /// Verifies that GetSessionCookie sets Path from request info provider.
    /// Path scoping ensures cookies are only sent to relevant endpoints.
    /// </summary>
    [Fact]
    public void GetSessionCookie_SetsPathFromRequestInfoProvider()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.Equal(PathBase, cookie.Options.Path);
        _requestInfoProvider.Verify(r => r.PathBase, Times.Once);
    }

    /// <summary>
    /// Verifies that GetSessionCookie sets Domain from options configuration.
    /// Domain scoping controls which hosts receive the session cookie.
    /// </summary>
    [Fact]
    public void GetSessionCookie_SetsDomainFromOptions()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.Equal(CookieDomain, cookie.Options.Domain);
    }

    /// <summary>
    /// Verifies that GetSessionCookie sets SameSite from options configuration.
    /// SameSite attribute provides CSRF protection and controls cross-site cookie behavior.
    /// </summary>
    [Fact]
    public void GetSessionCookie_SetsSameSiteFromOptions()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie = service.GetSessionCookie();

        // Assert
        Assert.Equal(SameSiteValue, cookie.Options.SameSite);
    }

    /// <summary>
    /// Verifies that GetSessionCookie returns a new Cookie instance each time.
    /// Each call should produce independent cookie objects with current configuration.
    /// </summary>
    [Fact]
    public void GetSessionCookie_ReturnsNewInstanceEachTime()
    {
        // Arrange
        _requestInfoProvider.Setup(r => r.IsHttps).Returns(true);
        _requestInfoProvider.Setup(r => r.PathBase).Returns(PathBase);
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var cookie1 = service.GetSessionCookie();
        var cookie2 = service.GetSessionCookie();

        // Assert
        Assert.NotSame(cookie1, cookie2);
        Assert.NotSame(cookie1.Options, cookie2.Options);
    }

    #endregion

    #region GetSessionState Tests

    /// <summary>
    /// Verifies that GetSessionState generates session state with correct format "hash.salt".
    /// Format is defined by OIDC Session Management spec for session state parameter.
    /// </summary>
    [Fact]
    public void GetSessionState_GeneratesCorrectFormat()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var sessionState = service.GetSessionState(request, SessionId);

        // Assert
        Assert.Contains(".", sessionState);
        var parts = sessionState.Split('.');
        Assert.Equal(2, parts.Length);
        Assert.NotEmpty(parts[0]); // hash
        Assert.NotEmpty(parts[1]); // salt
    }

    /// <summary>
    /// Verifies that GetSessionState uses client ID from authorization request.
    /// Client ID is part of the hash input per OIDC Session Management spec.
    /// </summary>
    [Fact]
    public void GetSessionState_UsesClientIdFromRequest()
    {
        // Arrange
        var request1 = CreateRequest(clientId: "client_1");
        var request2 = CreateRequest(clientId: "client_2");
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var state1 = service.GetSessionState(request1, SessionId);
        var state2 = service.GetSessionState(request2, SessionId);

        // Assert
        Assert.NotEqual(state1.Split('.')[0], state2.Split('.')[0]); // Different hashes due to different client IDs
    }

    /// <summary>
    /// Verifies that GetSessionState uses origin from redirect URI.
    /// Origin (scheme + host + port) is extracted from redirect URI for session state calculation.
    /// </summary>
    [Fact]
    public void GetSessionState_UsesOriginFromRedirectUri()
    {
        // Arrange
        var request1 = CreateRequest(redirectUri: new Uri("https://client1.example.com/callback"));
        var request2 = CreateRequest(redirectUri: new Uri("https://client2.example.com/callback"));
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var state1 = service.GetSessionState(request1, SessionId);
        var state2 = service.GetSessionState(request2, SessionId);

        // Assert
        Assert.NotEqual(state1.Split('.')[0], state2.Split('.')[0]); // Different hashes due to different origins
    }

    /// <summary>
    /// Verifies that GetSessionState uses the provided session ID.
    /// Session ID uniqueness ensures each session has distinct session state.
    /// </summary>
    [Fact]
    public void GetSessionState_UsesProvidedSessionId()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var state1 = service.GetSessionState(request, "session_1");
        var state2 = service.GetSessionState(request, "session_2");

        // Assert
        Assert.NotEqual(state1.Split('.')[0], state2.Split('.')[0]); // Different hashes due to different session IDs
    }

    /// <summary>
    /// Verifies that GetSessionState generates a random salt of 16 bytes (32 hex characters).
    /// Salt prevents rainbow table attacks and ensures unique session states.
    /// </summary>
    [Fact]
    public void GetSessionState_GeneratesRandomSalt()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var sessionState = service.GetSessionState(request, SessionId);
        var salt = sessionState.Split('.')[1];

        // Assert
        Assert.Equal(32, salt.Length); // 16 bytes = 32 hex characters
        Assert.All(salt, c => Assert.True(Uri.IsHexDigit(c)));
    }

    /// <summary>
    /// Verifies that different calls to GetSessionState generate different salts.
    /// Each session state must have a unique salt for security.
    /// </summary>
    [Fact]
    public void GetSessionState_GeneratesDifferentSalts()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var state1 = service.GetSessionState(request, SessionId);
        var state2 = service.GetSessionState(request, SessionId);

        // Assert
        var salt1 = state1.Split('.')[1];
        var salt2 = state2.Split('.')[1];
        Assert.NotEqual(salt1, salt2);
    }

    /// <summary>
    /// Verifies that same inputs with different salts produce different hashes.
    /// This ensures proper salt integration into the hash calculation.
    /// </summary>
    [Fact]
    public void GetSessionState_DifferentSaltsProduceDifferentHashes()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var state1 = service.GetSessionState(request, SessionId);
        var state2 = service.GetSessionState(request, SessionId);

        // Assert
        var hash1 = state1.Split('.')[0];
        var hash2 = state2.Split('.')[0];
        Assert.NotEqual(hash1, hash2);
    }

    /// <summary>
    /// Verifies that GetSessionState uses SHA256 for hashing.
    /// SHA256 provides sufficient security for session state integrity per OIDC spec.
    /// </summary>
    [Fact]
    public void GetSessionState_UsesSha256Hash()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var sessionState = service.GetSessionState(request, SessionId);
        var parts = sessionState.Split('.');
        var hash = parts[0];
        var salt = parts[1];

        // Manually compute expected hash
        var origin = request.RedirectUri!.GetOrigin();
        var input = string.Join(" ", request.ClientId, origin, SessionId, salt);
        var expectedHash = UrlTokenEncode(SHA256.HashData(Encoding.UTF8.GetBytes(input)));

        // Assert
        Assert.Equal(expectedHash, hash);
    }

    /// <summary>
    /// Verifies that GetSessionState produces URL-safe encoded hash.
    /// URL-safe encoding is required for session_state parameter in authorization responses.
    /// </summary>
    [Fact]
    public void GetSessionState_HashIsUrlSafeEncoded()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var sessionState = service.GetSessionState(request, SessionId);
        var hash = sessionState.Split('.')[0];

        // Assert
        // URL-safe encoding uses base64url: A-Z, a-z, 0-9, -, _ (no +, /, =)
        Assert.DoesNotContain("+", hash);
        Assert.DoesNotContain("/", hash);
        Assert.DoesNotContain("=", hash);
    }

    /// <summary>
    /// Verifies that GetSessionState produces hex string salt.
    /// Hex encoding ensures salt is URL-safe and easily parseable.
    /// </summary>
    [Fact]
    public void GetSessionState_SaltIsHexString()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var sessionState = service.GetSessionState(request, SessionId);
        var salt = sessionState.Split('.')[1];

        // Assert
        Assert.All(salt, c => Assert.True(Uri.IsHexDigit(c)));
    }

    /// <summary>
    /// Verifies that GetSessionState format uses dot separator between hash and salt.
    /// The "hash.salt" format is specified in OIDC Session Management spec.
    /// </summary>
    [Fact]
    public void GetSessionState_FormatHasDotSeparator()
    {
        // Arrange
        var request = CreateRequest();
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var sessionState = service.GetSessionState(request, SessionId);

        // Assert
        Assert.Matches(@"^[A-Za-z0-9_-]+\.[a-fA-F0-9]{32}$", sessionState);
    }

    /// <summary>
    /// Verifies that GetSessionState throws when request.RedirectUri is null.
    /// RedirectUri is required to extract origin for session state calculation.
    /// </summary>
    [Fact]
    public void GetSessionState_WhenRedirectUriIsNull_Throws()
    {
        // Arrange
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            RedirectUri = null
        };
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => service.GetSessionState(request, SessionId));
    }

    #endregion

    #region GetCheckSessionResponseAsync Tests

    /// <summary>
    /// Verifies that GetCheckSessionResponseAsync returns CheckSessionResponse.
    /// Response type is required for the check session endpoint per OIDC spec.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_ReturnsCheckSessionResponse()
    {
        // Arrange
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var response = await service.GetCheckSessionResponseAsync();

        // Assert
        Assert.NotNull(response);
    }

    /// <summary>
    /// Verifies that GetCheckSessionResponseAsync returns HTML content.
    /// The check session endpoint must return HTML with embedded JavaScript per OIDC spec.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_ReturnsHtmlContent()
    {
        // Arrange
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var response = await service.GetCheckSessionResponseAsync();

        // Assert
        Assert.NotNull(response.HtmlContent);
        Assert.NotEmpty(response.HtmlContent);
        Assert.Contains("<!DOCTYPE", response.HtmlContent, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that GetCheckSessionResponseAsync includes checkSession JavaScript functionality.
    /// The JavaScript implements session state monitoring per OIDC Session Management spec.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_ContainsCheckSessionJavaScript()
    {
        // Arrange
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var response = await service.GetCheckSessionResponseAsync();

        // Assert
        Assert.Contains("<script", response.HtmlContent, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that GetCheckSessionResponseAsync replaces cookie name placeholder with actual value.
    /// The template {{cookieName}} must be replaced with configured cookie name.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_ReplacesCookieNamePlaceholder()
    {
        // Arrange
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var response = await service.GetCheckSessionResponseAsync();

        // Assert
        Assert.DoesNotContain("{{cookieName}}", response.HtmlContent);
    }

    /// <summary>
    /// Verifies that GetCheckSessionResponseAsync properly escapes cookie name for JavaScript.
    /// JavaScript string escaping prevents XSS and syntax errors when injecting cookie name.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_EscapesCookieNameForJavaScript()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.CheckSession,
            CheckSessionCookie = new CheckSessionCookieOptions
            {
                Name = "Test\"Cookie'Name"
            }
        };
        var optionsSnapshot = new Mock<IOptionsSnapshot<OidcOptions>>(MockBehavior.Strict);
        optionsSnapshot.Setup(o => o.Value).Returns(options);
        var service = new SessionManagementService(optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var response = await service.GetCheckSessionResponseAsync();

        // Assert
        Assert.Contains(JavaScriptStringEncode("Test\"Cookie'Name", true), response.HtmlContent);
        Assert.DoesNotContain("Test\"Cookie'Name", response.HtmlContent); // Raw name should not appear
    }

    /// <summary>
    /// Verifies that GetCheckSessionResponseAsync includes correct cookie name in response.
    /// The cookie name is used by JavaScript to read session state from cookies.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_IncludesCorrectCookieName()
    {
        // Arrange
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var response = await service.GetCheckSessionResponseAsync();

        // Assert
        Assert.Equal(CookieName, response.CacheKey);
    }

    /// <summary>
    /// Verifies that GetCheckSessionResponseAsync reads embedded resource once per call.
    /// Each invocation should load and process the HTML template independently.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_ReadsEmbeddedResourceEachCall()
    {
        // Arrange
        var service = new SessionManagementService(_optionsSnapshot.Object, _requestInfoProvider.Object);

        // Act
        var response1 = await service.GetCheckSessionResponseAsync();
        var response2 = await service.GetCheckSessionResponseAsync();

        // Assert
        Assert.NotSame(response1, response2);
        Assert.Equal(response1.HtmlContent, response2.HtmlContent); // Content should be identical
    }

    /// <summary>
    /// Verifies that different cookie names produce different HTML content.
    /// Cookie name changes must be reflected in the generated HTML.
    /// </summary>
    [Fact]
    public async Task GetCheckSessionResponseAsync_DifferentCookieNamesProduceDifferentHtml()
    {
        // Arrange
        var options1 = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.CheckSession,
            CheckSessionCookie = new CheckSessionCookieOptions
            {
                Name = "CookieName1"
            }
        };
        var optionsSnapshot1 = new Mock<IOptionsSnapshot<OidcOptions>>(MockBehavior.Strict);
        optionsSnapshot1.Setup(o => o.Value).Returns(options1);
        var service1 = new SessionManagementService(optionsSnapshot1.Object, _requestInfoProvider.Object);
        var response1 = await service1.GetCheckSessionResponseAsync();

        var options2 = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.CheckSession,
            CheckSessionCookie = new CheckSessionCookieOptions
            {
                Name = "CookieName2"
            }
        };
        var optionsSnapshot2 = new Mock<IOptionsSnapshot<OidcOptions>>(MockBehavior.Strict);
        optionsSnapshot2.Setup(o => o.Value).Returns(options2);
        var service2 = new SessionManagementService(optionsSnapshot2.Object, _requestInfoProvider.Object);
        var response2 = await service2.GetCheckSessionResponseAsync();

        // Assert
        Assert.NotEqual(response1.HtmlContent, response2.HtmlContent);
        Assert.Contains(JavaScriptStringEncode("CookieName1", true), response1.HtmlContent);
        Assert.Contains(JavaScriptStringEncode("CookieName2", true), response2.HtmlContent);
    }

    #endregion

    #region Helper Methods

    private static AuthorizationRequest CreateRequest(
        string? clientId = null,
        Uri? redirectUri = null)
    {
        return new AuthorizationRequest
        {
            ClientId = clientId ?? ClientId,
            RedirectUri = redirectUri ?? new Uri(RedirectUriString),
        };
    }

    #endregion
}
