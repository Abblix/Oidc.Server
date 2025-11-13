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
using System.Net;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="TlsMetadataClientAuthenticator"/> verifying RFC 8705
/// metadata-based TLS client authentication via Subject DN and SAN validation.
/// </summary>
public class TlsMetadataClientAuthenticatorTests
{
    private readonly Mock<ILogger<TlsMetadataClientAuthenticator>> _loggerMock;
    private readonly Mock<IClientInfoProvider> _clientInfoProviderMock;
    private readonly TlsMetadataClientAuthenticator _authenticator;

    public TlsMetadataClientAuthenticatorTests()
    {
        _loggerMock = new Mock<ILogger<TlsMetadataClientAuthenticator>>();
        _clientInfoProviderMock = new Mock<IClientInfoProvider>();

        _authenticator = new TlsMetadataClientAuthenticator(
            _loggerMock.Object,
            _clientInfoProviderMock.Object);
    }

    /// <summary>
    /// Verifies authenticator advertises tls_client_auth method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldContainTlsClientAuth()
    {
        // Act
        var methods = _authenticator.ClientAuthenticationMethodsSupported;

        // Assert
        Assert.Contains(ClientAuthenticationMethods.TlsClientAuth, methods);
    }

    /// <summary>
    /// Verifies authentication fails when no client certificate is provided.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNoCertificate_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = null,
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client_id is not provided.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task TryAuthenticateClientAsync_WithNoClientId_ShouldReturnNull(string? clientId)
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = clientId!,
            ClientCertificate = CreateCertificate("CN=Test Client"),
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client is not found.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithUnknownClient_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = "unknown-client",
            ClientCertificate = CreateCertificate("CN=Test Client"),
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("unknown-client"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client uses different authentication method.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost)]
    [InlineData(ClientAuthenticationMethods.SelfSignedTlsClientAuth)]
    public async Task TryAuthenticateClientAsync_WithDifferentAuthMethod_ShouldReturnNull(string authMethod)
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = CreateCertificate("CN=Test Client"),
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = authMethod,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client has no TLS metadata configured.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNoTlsMetadata_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = CreateCertificate("CN=Test Client"),
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = null,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication succeeds with matching Subject DN only.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingSubjectDn_ShouldReturnClient()
    {
        // Arrange
        const string subjectDn = "CN=client.example.com,O=Example Corp,C=US";
        var cert = CreateCertificate(subjectDn);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SubjectDn = subjectDn,
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies authentication fails with non-matching Subject DN.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNonMatchingSubjectDn_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateCertificate("CN=client.example.com,O=Example Corp");

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SubjectDn = "CN=different.example.com,O=Example Corp",
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication succeeds with matching SAN DNS name.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingSanDns_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            dnsNames: ["client.example.com"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanDns = ["client.example.com"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies authentication fails with non-matching SAN DNS name.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNonMatchingSanDns_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            dnsNames: ["client.example.com"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanDns = ["different.example.com"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies DNS name matching is case-insensitive.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithDnsNameDifferentCase_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            dnsNames: ["CLIENT.EXAMPLE.COM"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanDns = ["client.example.com"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Verifies authentication succeeds with matching SAN URI.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingSanUri_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            uris: [new Uri("https://example.com/client")]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanUris = [new Uri("https://example.com/client")],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies authentication succeeds with matching SAN IP address.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingSanIp_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            ipAddresses: [IPAddress.Parse("192.168.1.1")]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanIps = ["192.168.1.1"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies authentication succeeds with IPv6 address.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingIpv6_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            ipAddresses: [IPAddress.Parse("2001:db8::1")]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanIps = ["2001:db8::1"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Verifies authentication succeeds with matching SAN email address.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingSanEmail_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            emails: ["client@example.com"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanEmails = ["client@example.com"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies email matching is case-insensitive.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithEmailDifferentCase_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            emails: ["CLIENT@EXAMPLE.COM"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanEmails = ["client@example.com"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Verifies authentication succeeds with all metadata types matching.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithAllMetadataMatching_ShouldReturnClient()
    {
        // Arrange
        const string subjectDn = "CN=client.example.com,O=Example Corp";
        var cert = CreateCertificateWithSan(
            subjectDn,
            dnsNames: ["client.example.com", "www.example.com"],
            uris: [new Uri("https://example.com/client")],
            ipAddresses: [IPAddress.Parse("192.168.1.1")],
            emails: ["client@example.com"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SubjectDn = subjectDn,
                SanDns = ["client.example.com", "www.example.com"],
                SanUris = [new Uri("https://example.com/client")],
                SanIps = ["192.168.1.1"],
                SanEmails = ["client@example.com"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies authentication fails when certificate has no SAN but SAN is required.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNoSanButSanRequired_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateCertificate("CN=Test Client");

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanDns = ["client.example.com"],
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when some required SAN entries are missing.
    /// All required entries must be present.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithSomeSanEntriesMissing_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            dnsNames: ["client.example.com"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanDns = ["client.example.com", "www.example.com"], // Requires 2 but cert has only 1
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication succeeds when certificate has more SAN entries than required.
    /// Certificate can have additional entries not specified in requirements.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithExtraSanEntries_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateCertificateWithSan(
            "CN=Test Client",
            dnsNames: ["client.example.com", "www.example.com", "api.example.com"]);

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions
            {
                SanDns = ["client.example.com"], // Requires only 1, cert has 3
            },
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Creates a certificate with specified subject DN.
    /// </summary>
    private static X509Certificate2 CreateCertificate(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));
    }

    /// <summary>
    /// Creates a certificate with specified Subject DN and SAN extension.
    /// </summary>
    private static X509Certificate2 CreateCertificateWithSan(
        string subjectName,
        string[]? dnsNames = null,
        Uri[]? uris = null,
        IPAddress[]? ipAddresses = null,
        string[]? emails = null)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();

        if (dnsNames != null)
        {
            foreach (var dns in dnsNames)
                sanBuilder.AddDnsName(dns);
        }

        if (uris != null)
        {
            foreach (var uri in uris)
                sanBuilder.AddUri(uri);
        }

        if (ipAddresses != null)
        {
            foreach (var ip in ipAddresses)
                sanBuilder.AddIpAddress(ip);
        }

        if (emails != null)
        {
            foreach (var email in emails)
                sanBuilder.AddEmailAddress(email);
        }

        request.CertificateExtensions.Add(sanBuilder.Build());

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));
    }
}
