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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="TlsClientAuthValidator"/> verifying RFC 8705
/// mTLS client authentication metadata validation.
/// </summary>
public class TlsClientAuthValidatorTests
{
    private readonly TlsClientAuthValidator _validator = new();

    private ClientRegistrationValidationContext CreateContext(ClientRegistrationRequest request)
        => new(request);

    /// <summary>
    /// Verifies validation succeeds when not using tls_client_auth method.
    /// Validator should skip validation for other authentication methods.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentAuthMethod_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation fails when using tls_client_auth without any metadata.
    /// At least one identification field must be provided.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTlsClientAuthNoMetadata_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("at least one", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies validation succeeds with valid Subject DN.
    /// RFC 4514 compliant DN should pass validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidSubjectDn_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSubjectDn = "CN=client.example.com,O=Example Corp,C=US",
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation fails with invalid Subject DN format.
    /// Malformed DN should be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidSubjectDn_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSubjectDn = "not a valid DN format!@#",
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("RFC 4514", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies validation succeeds with valid DNS names.
    /// Non-empty DNS names without whitespace should pass.
    /// </summary>
    [Theory]
    [InlineData("example.com")]
    [InlineData("client.example.com")]
    [InlineData("*.example.com")]
    public async Task ValidateAsync_WithValidDnsName_ShouldReturnNull(string dnsName)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanDns = [dnsName],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation fails with empty DNS name.
    /// Empty strings are not valid DNS names.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyDnsName_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanDns = [""],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("must not be empty", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies validation fails with DNS names containing whitespace.
    /// Whitespace characters are not allowed in DNS names.
    /// </summary>
    [Theory]
    [InlineData("example .com")]
    [InlineData("example\n.com")]
    [InlineData("example\r.com")]
    public async Task ValidateAsync_WithDnsNameContainingWhitespace_ShouldReturnError(string dnsName)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanDns = [dnsName],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Invalid DNS name", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies validation succeeds with absolute URIs.
    /// URIs with scheme and host should pass.
    /// </summary>
    [Theory]
    [InlineData("https://example.com")]
    [InlineData("ldap://ldap.example.com")]
    [InlineData("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6")]
    public async Task ValidateAsync_WithAbsoluteUri_ShouldReturnNull(string uri)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanUri = [new Uri(uri)],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with valid IPv4 addresses.
    /// Standard IPv4 notation should pass.
    /// </summary>
    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.1")]
    public async Task ValidateAsync_WithValidIPv4_ShouldReturnNull(string ip)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanIp = [ip],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with valid IPv6 addresses.
    /// Standard IPv6 notation should pass.
    /// </summary>
    [Theory]
    [InlineData("2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    public async Task ValidateAsync_WithValidIPv6_ShouldReturnNull(string ip)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanIp = [ip],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation fails with invalid IP addresses.
    /// Malformed IP addresses should be rejected.
    /// </summary>
    [Theory]
    [InlineData("256.1.1.1")]
    [InlineData("not-an-ip")]
    public async Task ValidateAsync_WithInvalidIp_ShouldReturnError(string ip)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanIp = [ip],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Invalid IP address", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies validation succeeds with valid email addresses.
    /// Basic email format with @ character should pass.
    /// </summary>
    [Theory]
    [InlineData("client@example.com")]
    [InlineData("test.user@example.org")]
    [InlineData("user+tag@example.co.uk")]
    public async Task ValidateAsync_WithValidEmail_ShouldReturnNull(string email)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanEmail = [email],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation fails with invalid email addresses.
    /// Emails without @ character or empty should be rejected.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not-an-email")]
    public async Task ValidateAsync_WithInvalidEmail_ShouldReturnError(string email)
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanEmail = [email],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Invalid email", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies validation succeeds with multiple metadata types.
    /// Combination of DN, DNS, URI, IP, and email should all be validated.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleValidMetadata_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSubjectDn = "CN=client.example.com,O=Example Corp",
            TlsClientAuthSanDns = ["client.example.com", "*.example.com"],
            TlsClientAuthSanUri = [new Uri("https://example.com")],
            TlsClientAuthSanIp = ["192.168.1.1"],
            TlsClientAuthSanEmail = ["client@example.com"],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation fails on first invalid entry when multiple provided.
    /// Should return error for the first validation failure encountered.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMixedValidInvalidMetadata_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuthSanDns = ["valid.example.com", "invalid dns name"],
        });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Invalid DNS name", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }
}
