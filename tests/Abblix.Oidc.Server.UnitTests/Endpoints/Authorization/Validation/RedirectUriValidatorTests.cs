// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="RedirectUriValidator"/> verifying redirect URI validation
/// per RFC 6749 Section 3.1.2. Tests cover exact URI matching, open redirect prevention,
/// query parameter handling, and security-critical redirect URI validation rules.
/// </summary>
public class RedirectUriValidatorTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string RegisteredUri = "https://client.example.com/callback";
    private const string RegisteredUri2 = "https://client.example.com/callback2";

    private readonly Mock<ILogger<RedirectUriValidator>> _logger;
    private readonly RedirectUriValidator _validator;

    public RedirectUriValidatorTests()
    {
        _logger = new Mock<ILogger<RedirectUriValidator>>();
        _logger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
        _validator = new RedirectUriValidator(_logger.Object);
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing, for a native client, which may redirect to each kind of
    /// URI these tests match: https, a private-use scheme and http on a loopback host.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        Uri? redirectUri,
        params Uri[] registeredUris)
        => CreateContextFor(ApplicationTypes.Native, redirectUri, registeredUris);

    private static AuthorizationValidationContext CreateContextFor(
        string applicationType,
        Uri? redirectUri,
        params Uri[] registeredUris)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = redirectUri,
            Scope = [Scopes.OpenId],
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            ApplicationType = applicationType,
            RedirectUris = registeredUris,
        };

        return new AuthorizationValidationContext(request)
        {
            Clients = Mock.Of<IClientInfoProvider>(),
            ClientInfo = clientInfo,
            ResponseMode = ResponseModes.Query,
        };
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts exact match with registered redirect URI.
    /// Per RFC 6749 Section 3.1.2.3, redirect URI must match one of registered URIs exactly.
    /// Critical security requirement preventing open redirect attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExactMatchingUri_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, redirectUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI not in registered URIs.
    /// Per RFC 6749, unregistered redirect URIs must be rejected.
    /// Critical for preventing authorization code leakage to attacker-controlled endpoints.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnregisteredUri_ShouldReturnError()
    {
        // Arrange
        var redirectUri = new Uri("https://attacker.example.com/steal");
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("not valid", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects null redirect URI.
    /// Per RFC 6749, redirect_uri is required in authorization requests.
    /// Critical validation preventing malformed requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullRedirectUri_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(null, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI matching one of multiple registered URIs.
    /// Per RFC 6749, clients may register multiple redirect URIs.
    /// Tests validator correctly handles multi-URI client configurations.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleRegisteredUris_ShouldAcceptMatchingOne()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri2);
        var registeredUri1 = new Uri(RegisteredUri);
        var registeredUri2 = new Uri(RegisteredUri2);
        var context = CreateContext(redirectUri, registeredUri1, registeredUri2);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with query parameters matching registered URI.
    /// Per RFC 6749 Section 3.1.2, redirect URI comparison includes query component.
    /// Tests that query parameters must match exactly.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithQueryParameters_RequiresExactMatch()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback?param=value");
        var redirectUri = new Uri("https://client.example.com/callback?param=value");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different query parameters.
    /// Per RFC 6749, query component must match exactly in redirect URI.
    /// Critical security check preventing parameter injection attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentQueryParameters_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback?param=value1");
        var redirectUri = new Uri("https://client.example.com/callback?param=value2");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with additional query parameters.
    /// Redirect URI must match registered URI exactly, including query string.
    /// Prevents attackers from adding tracking or malicious parameters.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAdditionalQueryParameters_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/callback?extra=param");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with fragment matching registered URI.
    /// Per RFC 6749 Section 3.1.2, fragment component is included in URI comparison.
    /// Tests exact fragment matching requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFragment_RequiresExactMatch()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback#section");
        var redirectUri = new Uri("https://client.example.com/callback#section");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// RFC 6749 section 3.1.2: "The endpoint URI MUST NOT include a fragment component." A redirect URI carrying a
    /// fragment is refused, whether the registered URI carries none or another one, and so is one carrying user
    /// information the registered URI lacks.
    /// </summary>
    [Theory]
    [InlineData("https://client.example.com/callback", "https://client.example.com/callback#section2")]
    [InlineData("https://client.example.com/callback#section1", "https://client.example.com/callback#section2")]
    [InlineData("https://client.example.com/callback", "https://user@client.example.com/callback")]
    public async Task ValidateAsync_WithFragmentOrUserInfo_ShouldReturnError(string registered, string requested)
    {
        var context = CreateContext(new Uri(requested), new Uri(registered));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync enforces case-sensitive URI comparison.
    /// Per RFC 3986, URI scheme and host are case-insensitive, but path is case-sensitive.
    /// Tests that path differences in casing are rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentPathCasing_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/Callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// RFC 9700 section 4.1.3: the server "MUST ensure that the two URIs are equal; see Section 6.2.1 of [RFC3986],
    /// Simple String Comparison". A spelling RFC 3986 normalizes to the registered URI is not that URI: host case, a
    /// scheme in capitals, a default port written out, an encoded unreserved character, a dot segment, and an IPv6
    /// loopback literal written in full, whose port alone may differ (RFC 8252 section 7.3).
    /// </summary>
    [Theory]
    [InlineData("https://client.example.com/callback", "https://CLIENT.EXAMPLE.COM/callback")]
    [InlineData("https://client.example.com/callback", "HTTPS://client.example.com/callback")]
    [InlineData("https://client.example.com/callback", "https://client.example.com:443/callback")]
    [InlineData("https://client.example.com:443/callback", "https://client.example.com/callback")]
    [InlineData("https://client.example.com/~user", "https://client.example.com/%7Euser")]
    [InlineData("https://client.example.com/callback", "https://client.example.com/a/../callback")]
    [InlineData("http://[::1]:61023/oauth2redirect", "http://[0:0:0:0:0:0:0:1]:61024/oauth2redirect")]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://127.0.0.1:51005/oauth2REDIRECT")]
    public async Task ValidateAsync_ASpellingNormalizedToTheRegisteredUri_ShouldReturnError(
        string registered, string requested)
    {
        var context = CreateContext(new Uri(requested), new Uri(registered));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(ErrorCodes.InvalidRequest, result?.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different scheme.
    /// Per RFC 6749, scheme must match exactly (http vs https).
    /// Critical security check preventing protocol downgrade attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentScheme_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("http://client.example.com/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different port.
    /// Per RFC 6749, port must match exactly in redirect URI.
    /// Critical for preventing port-based redirect attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentPort_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com:443/callback");
        var redirectUri = new Uri("https://client.example.com:8443/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with trailing slash when registered without.
    /// Per RFC 6749, redirect URI must match exactly including trailing slashes.
    /// Tests strict path matching requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTrailingSlashDifference_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/callback/");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with different path.
    /// Path component must match exactly between redirect and registered URIs.
    /// Prevents path traversal and directory-based attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentPath_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/different");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects URI with additional path segments.
    /// Prevents attackers from appending malicious path segments.
    /// Critical for preventing open redirect via path manipulation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAdditionalPathSegments_ShouldReturnError()
    {
        // Arrange
        var registeredUri = new Uri("https://client.example.com/callback");
        var redirectUri = new Uri("https://client.example.com/callback/extra");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts localhost redirect URI.
    /// RFC 8252 section 8.3 calls localhost NOT RECOMMENDED for native apps, so it keeps an exact match, port included.
    /// Tests support for native application redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLocalhostUri_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("http://localhost:8080/callback");
        var registeredUri = new Uri("http://localhost:8080/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts custom scheme redirect URI.
    /// Per RFC 8252 Section 7.2, native apps may use custom URI schemes.
    /// Tests support for mobile/desktop application deep linking.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomScheme_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("com.example.app:/callback");
        var registeredUri = new Uri("com.example.app:/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects empty registered URIs array.
    /// Client with no registered redirect URIs should not pass validation.
    /// Critical check preventing misconfigured client exploitation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoRegisteredUris_ShouldReturnError()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync sets ValidRedirectUri in context on success.
    /// Per validator contract, successful validation must populate ValidRedirectUri.
    /// Critical for downstream authorization flow processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetValidRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, redirectUri);
        Assert.Null(context.ValidRedirectUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.ValidRedirectUri);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync does not set ValidRedirectUri on failure.
    /// Failed validation must not populate ValidRedirectUri.
    /// Ensures error responses don't include invalid redirect information.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnFailure_ShouldNotSetValidRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri("https://attacker.example.com/steal");
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync logs warning on invalid redirect URI.
    /// Per security best practices, invalid redirect attempts should be logged.
    /// Critical for security monitoring and attack detection.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidUri_ShouldLogWarning()
    {
        // Arrange
        var redirectUri = new Uri("https://attacker.example.com/steal");
        var registeredUri = new Uri(RegisteredUri);
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        _logger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v!.ToString()!.Contains("invalid")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with encoded characters.
    /// Per RFC 3986, URIs may contain percent-encoded characters.
    /// Tests validator handles URI encoding correctly.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEncodedCharacters_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/callback?param=value%20with%20spaces");
        var registeredUri = new Uri("https://client.example.com/callback?param=value%20with%20spaces");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts loopback IPv4 address.
    /// Per RFC 8252 Section 8.3, loopback IP addresses are allowed for native apps.
    /// Tests support for IPv4 loopback redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLoopbackIPv4_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("http://127.0.0.1:8080/callback");
        var registeredUri = new Uri("http://127.0.0.1:8080/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts loopback IPv6 address.
    /// Per RFC 8252, IPv6 loopback [::1] is allowed for native apps.
    /// Tests support for IPv6 loopback redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLoopbackIPv6_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("http://[::1]:8080/callback");
        var registeredUri = new Uri("http://[::1]:8080/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// A desktop app takes a free port from the operating system at sign-in, so the port it sends differs from the
    /// one it registered. RFC 8252 section 7.3 requires any port to be allowed for a loopback IP redirect URI, and
    /// section 8.4 keeps every other component an exact match.
    /// </summary>
    [Theory]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://127.0.0.1:51005/oauth2redirect")]
    [InlineData("http://[::1]:61023/oauth2redirect", "http://[::1]:61024/oauth2redirect")]
    [InlineData("http://127.0.0.1/oauth2redirect", "http://127.0.0.1:51005/oauth2redirect")]
    [InlineData("http://[::1]/oauth2redirect", "http://[::1]:61024/oauth2redirect")]
    public async Task ValidateAsync_LoopbackIpWithAnotherPort_ShouldSucceed(string registered, string requested)
    {
        var redirectUri = new Uri(requested);
        var context = CreateContext(redirectUri, new Uri(registered));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// A client registering several redirect URIs keeps the loopback rule for the loopback one among them, which is
    /// how an app binding either IPv4 or IPv6 registers both literals (RFC 8252 section 7.3).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_LoopbackIpAmongSeveralRegistered_AcceptsAnotherPort()
    {
        var redirectUri = new Uri("http://[::1]:61024/oauth2redirect");
        var context = CreateContext(
            redirectUri,
            new Uri(RegisteredUri),
            new Uri("http://127.0.0.1:51004/oauth2redirect"),
            new Uri("http://[::1]:61023/oauth2redirect"));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
        Assert.Equal(redirectUri, context.ValidRedirectUri);
    }

    /// <summary>
    /// Only the port of a loopback IP redirect URI is free (RFC 8252 section 8.4). A different path, host, scheme or
    /// query is still refused, as is a URI carrying user information or a fragment, and so is another port on <c>localhost</c>, on a loopback address other than
    /// <c>127.0.0.1</c> or on an <c>https</c> loopback URI, none of which section 7.3 covers.
    /// </summary>
    [Theory]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://127.0.0.1:51005/other")]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://127.0.0.2:51005/oauth2redirect")]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "https://127.0.0.1:51005/oauth2redirect")]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://127.0.0.1:51005/oauth2redirect?next=1")]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://[::1]:51005/oauth2redirect")]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://user@127.0.0.1:51005/oauth2redirect")]
    [InlineData("http://127.0.0.1:51004/oauth2redirect", "http://127.0.0.1:51005/oauth2redirect#done")]
    [InlineData("http://localhost:51004/oauth2redirect", "http://localhost:51005/oauth2redirect")]
    [InlineData("http://127.0.0.2:51004/oauth2redirect", "http://127.0.0.2:51005/oauth2redirect")]
    [InlineData("https://127.0.0.1:51004/oauth2redirect", "https://127.0.0.1:51005/oauth2redirect")]
    public async Task ValidateAsync_LoopbackWithAnotherComponent_ShouldReturnError(string registered, string requested)
    {
        var context = CreateContext(new Uri(requested), new Uri(registered));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts URI with international domain name.
    /// Per RFC 3490, internationalized domain names (IDN) are valid URIs.
    /// Tests support for non-ASCII domain names.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInternationalDomainName_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("https://παράδειγμα.example.com/callback");
        var registeredUri = new Uri("https://παράδειγμα.example.com/callback");
        var context = CreateContext(redirectUri, registeredUri);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// FAPI 1.0 Part 1 section 5.2.2, taken in by Part 2 section 5.2.2: the server "shall require the value of
    /// redirect_uri to exactly match one of the pre-registered redirect URIs" and "shall require redirect URIs to use
    /// the https scheme". For a client held to FAPI 1.0 Advanced a loopback redirect URI on another port, which RFC 8252
    /// section 7.3 otherwise admits, is refused, and so is an http one even where registered; the exact https URI
    /// passes, and a client held to no profile keeps the loopback allowance.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, "http://127.0.0.1:8080/cb", "http://127.0.0.1:8080/cb", false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, "https://127.0.0.1:8443/cb", "https://127.0.0.1:9443/cb", false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, "https://127.0.0.1:8443/cb", "https://127.0.0.1:8443/cb", true)]
    [InlineData(null, "http://127.0.0.1:8080/cb", "http://127.0.0.1:9090/cb", true)]
    public async Task ValidateAsync_Fapi1Advanced_RequiresAnExactHttpsRedirectUri(
        ClientSecurityProfile? profile, string registered, string requested, bool accepted)
    {
        var context = CreateContext(new Uri(requested), new Uri(registered));
        context.ClientInfo.SecurityProfile = profile;

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(accepted, result == null);
    }

    /// <summary>
    /// A client the host's own store supplies never met the check of the settings, so the endpoint holds its redirect URI
    /// to the same rule: a web client redirects only to https (RFC 9700 section 2.6, RFC 8252 section 7.1), even to a
    /// URI it registered, while a native client keeps the loopback and private-use redirects.
    /// </summary>
    [Theory]
    [InlineData(ApplicationTypes.Web, "http://client.example.com/callback", false)]
    [InlineData(ApplicationTypes.Web, "http://127.0.0.1:8080/callback", false)]
    [InlineData(ApplicationTypes.Web, "com.example.app:/callback", false)]
    [InlineData(ApplicationTypes.Web, "https://client.example.com/callback", true)]
    [InlineData(ApplicationTypes.Native, "http://127.0.0.1:8080/callback", true)]
    [InlineData(ApplicationTypes.Native, "http://client.example.com/callback", false)]
    [InlineData(ApplicationTypes.Native, "myapp:/callback", false)]
    public async Task ValidateAsync_ARegisteredRedirectUri_IsHeldToTheSchemesOfItsClientType(
        string applicationType, string uri, bool accepted)
    {
        var context = CreateContextFor(applicationType, new Uri(uri), new Uri(uri));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(accepted, result == null);
    }

    /// <summary>
    /// A request object binds its redirect_uri without the model validation that keeps a relative one out of a plain
    /// request, so a relative redirect_uri from a client held to FAPI 1.0 Advanced is refused like any other that
    /// matches nothing, rather than failing on its scheme.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi1Advanced_ARelativeRedirectUri_IsRefused()
    {
        var context = CreateContext(new Uri("callback", UriKind.Relative), new Uri(RegisteredUri));
        context.ClientInfo.SecurityProfile = ClientSecurityProfile.Fapi1Advanced;

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(ErrorCodes.InvalidRequest, result?.Error);
    }

    /// <summary>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 4.1.1: redirect_uri is "OPTIONAL if only one redirect URI is
    /// registered for this client". A request without the openid scope from a client with one registered URI is served
    /// at that URI, which the request goes on carrying, and remembers that the client named none.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OAuthRequestWithoutRedirectUri_OneRegistered_IsServedAtIt()
    {
        var registered = new Uri(RegisteredUri);
        var context = CreateContext(null, registered);
        context.Request = context.Request with { Scope = ["api"] };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
        Assert.Equal(registered, context.ValidRedirectUri);
        Assert.Equal(registered, context.Request.RedirectUri);
        Assert.True(context.Request.ClientNamedNoRedirectUri);
    }

    /// <summary>
    /// offline_access beside the scope, or in the client's default, is judged here before the flow type is settled, by
    /// the scope the request is served with: an OAuth request carrying it is served at the sole URI, an OpenID Connect
    /// one is refused. offline_access alone is served as named when it is received (OpenID Connect Core 1.0 section 11:
    /// prompt=consent for a client that may receive refresh tokens), a plain OAuth request, and is ignored otherwise,
    /// the request then served the client's default.
    /// </summary>
    [Theory]
    [InlineData(new[] { Scopes.Profile, Scopes.OfflineAccess }, null, false, true)]
    [InlineData(new[] { Scopes.OpenId, Scopes.OfflineAccess }, null, false, false)]
    [InlineData(new string[0], new[] { Scopes.Profile, Scopes.OfflineAccess }, false, true)]
    [InlineData(new string[0], new[] { Scopes.OpenId, Scopes.OfflineAccess }, false, false)]
    [InlineData(new[] { Scopes.OfflineAccess }, new[] { Scopes.OpenId }, false, false)]
    [InlineData(new[] { Scopes.OfflineAccess }, new[] { Scopes.OpenId }, true, true)]
    public async Task ValidateAsync_RequestWithoutRedirectUri_AndOfflineAccess_IsJudgedByTheOpenIdScope(
        string[] named, string[]? defaultScope, bool promptConsent, bool served)
    {
        var registered = new Uri(RegisteredUri);
        var context = CreateContext(null, registered);
        context.Request = context.Request with
        {
            Scope = named,
            Prompt = promptConsent ? [Prompts.Consent] : null,
        };
        context.ClientInfo.DefaultScope = defaultScope;
        context.ClientInfo.AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken];
        context.ClientInfo.OfflineAccess = OfflineAccess.ConsentRequired;

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(served, result == null);
        Assert.Equal(served ? registered : null, context.ValidRedirectUri);
    }

    /// <summary>
    /// A request naming its redirect URI is not marked as one that named none.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RequestNamingItsRedirectUri_IsNotMarkedAsNamingNone()
    {
        var registered = new Uri(RegisteredUri);
        var context = CreateContext(registered, registered);
        context.Request = context.Request with { Scope = ["api"] };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
        Assert.False(context.Request.ClientNamedNoRedirectUri);
    }

    /// <summary>
    /// A request coming back from a page carries the URI it was served at, and keeps the mark that its client named
    /// none, so the token endpoint still knows it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RequestComingBack_KeepsTheMarkThatItsClientNamedNone()
    {
        var registered = new Uri(RegisteredUri);
        var context = CreateContext(registered, registered);
        context.Request = context.Request with { Scope = ["api"], ClientNamedNoRedirectUri = true };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
        Assert.True(context.Request.ClientNamedNoRedirectUri);
    }

    /// <summary>
    /// OAuth 2.1 section 2.3.2: "If multiple redirect URIs have been registered for a client, the client MUST include a
    /// redirect URI with the authorization request". An OpenID Connect request keeps redirect_uri required (OpenID
    /// Connect Core 1.0 section 3.1.2.1), whether it names openid or is served a default scope carrying it.
    /// </summary>
    [Theory]
    [InlineData("api", null, 2)]
    [InlineData(Scopes.OpenId, null, 1)]
    [InlineData(null, Scopes.OpenId, 1)]
    public async Task ValidateAsync_RequestWithoutRedirectUri_IsRefusedUnlessOAuthWithOneRegistered(
        string? named, string? defaultScope, int registeredCount)
    {
        Uri[] registered = registeredCount == 1
            ? [new Uri(RegisteredUri)]
            : [new Uri(RegisteredUri), new Uri(RegisteredUri2)];
        var context = CreateContext(null, registered);
        context.Request = context.Request with { Scope = named is null ? [] : [named] };
        context.ClientInfo.DefaultScope = defaultScope is null ? null : [defaultScope];

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(ErrorCodes.InvalidRequest, result?.Error);
        Assert.Null(context.ValidRedirectUri);
        Assert.Null(context.Request.RedirectUri);
    }

    /// <summary>
    /// FAPI 1.0 Part 1 section 5.2.2 clause 9: the server "shall require the redirect_uri in the authorization request",
    /// and FAPI 2.0 Security Profile section 5.3.2.2 clause 6 "shall require the redirect_uri parameter in pushed
    /// authorization requests", so a client held to either names it even with one URI registered.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    public async Task ValidateAsync_FapiClientWithoutRedirectUri_IsRefused(ClientSecurityProfile profile)
    {
        var context = CreateContextFor(ApplicationTypes.Web, null, new Uri(RegisteredUri));
        context.Request = context.Request with { Scope = ["api"] };
        context.ClientInfo.SecurityProfile = profile;

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(ErrorCodes.InvalidRequest, result?.Error);
        Assert.Null(context.ValidRedirectUri);
    }

    /// <summary>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 2.3: "The query string component MUST NOT include any parameters
    /// defined for use in the authorization response". A client the host's own store supplies never met the check of
    /// the settings, so the endpoint refuses such a registered redirect URI too, and keeps one whose query names
    /// another parameter.
    /// </summary>
    [Theory]
    [InlineData("https://client.example.com/callback?code=1", false)]
    [InlineData("https://client.example.com/callback?iss=x", false)]
    [InlineData("https://client.example.com/callback?tenant=a", true)]
    public async Task ValidateAsync_ARegisteredRedirectUriNamingAResponseParameter_IsRefused(string uri, bool accepted)
    {
        var context = CreateContextFor(ApplicationTypes.Web, new Uri(uri), new Uri(uri));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(accepted, result == null);
    }

    /// <summary>
    /// The URI a request naming none is served at answers to the schemes of its client like a named one: a web client
    /// is not served at an http URI it registered.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RequestWithoutRedirectUri_TheRegisteredUriIsHeldToTheSchemesOfItsClientType()
    {
        var context = CreateContextFor(ApplicationTypes.Web, null, new Uri("http://client.example.com/callback"));
        context.Request = context.Request with { Scope = ["api"] };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(ErrorCodes.InvalidRequest, result?.Error);
        Assert.Null(context.ValidRedirectUri);
    }
}
