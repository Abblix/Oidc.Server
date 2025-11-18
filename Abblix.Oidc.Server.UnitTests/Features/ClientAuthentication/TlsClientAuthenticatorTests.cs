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
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="TlsClientAuthenticator"/> verifying RFC 8705
/// self-signed TLS client authentication via JWKS public key matching.
/// </summary>
public class TlsClientAuthenticatorTests
{
    private readonly Mock<ILogger<TlsClientAuthenticator>> _loggerMock;
    private readonly Mock<IClientInfoProvider> _clientInfoProviderMock;
    private readonly Mock<IClientKeysProvider> _clientKeysProviderMock;
    private readonly TlsClientAuthenticator _authenticator;

    public TlsClientAuthenticatorTests()
    {
        _loggerMock = new Mock<ILogger<TlsClientAuthenticator>>();
        _clientInfoProviderMock = new Mock<IClientInfoProvider>();
        _clientKeysProviderMock = new Mock<IClientKeysProvider>();

        _authenticator = new TlsClientAuthenticator(
            _loggerMock.Object,
            _clientInfoProviderMock.Object,
            _clientKeysProviderMock.Object);
    }

    /// <summary>
    /// Verifies authenticator advertises self_signed_tls_client_auth method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldContainSelfSignedTlsClientAuth()
    {
        // Act
        var methods = _authenticator.ClientAuthenticationMethodsSupported;

        // Assert
        Assert.Contains(ClientAuthenticationMethods.SelfSignedTlsClientAuth, methods);
    }

    /// <summary>
    /// Verifies authentication fails when no client certificate is provided.
    /// RFC 8705 requires a certificate for mTLS authentication.
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
    /// Client identification is required for JWKS lookup.
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
            ClientCertificate = CreateRsaCertificate(),
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client is not found in the system.
    /// Unknown clients cannot be authenticated.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithUnknownClient_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = "unknown-client",
            ClientCertificate = CreateRsaCertificate(),
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
    /// Only self_signed_tls_client_auth is supported by this authenticator.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth)]
    public async Task TryAuthenticateClientAsync_WithDifferentAuthMethod_ShouldReturnNull(string authMethod)
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = CreateRsaCertificate(),
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
    /// Verifies authentication succeeds when RSA certificate public key matches JWKS.
    /// Tests the core functionality of self-signed mTLS authentication.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingRsaCertificate_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateRsaCertificate();
        var certJwk = cert.ToJsonWebKey();

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(new[] { certJwk }.ToAsyncEnumerable());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies authentication succeeds when ECDSA certificate public key matches JWKS.
    /// Tests ECDSA support in addition to RSA.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingEcdsaCertificate_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateEcdsaCertificate();
        var certJwk = cert.ToJsonWebKey();

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(new[] { certJwk }.ToAsyncEnumerable());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies authentication fails when RSA certificate doesn't match any JWKS key.
    /// Public key matching is required for authentication.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNonMatchingRsaCertificate_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateRsaCertificate();
        var differentCert = CreateRsaCertificate();
        var differentJwk = differentCert.ToJsonWebKey();

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(new[] { differentJwk }.ToAsyncEnumerable());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when ECDSA certificate doesn't match any JWKS key.
    /// Tests mismatch detection for ECDSA keys.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNonMatchingEcdsaCertificate_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateEcdsaCertificate();
        var differentCert = CreateEcdsaCertificate();
        var differentJwk = differentCert.ToJsonWebKey();

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(new[] { differentJwk }.ToAsyncEnumerable());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when JWKS is empty.
    /// At least one matching key is required.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithEmptyJwks_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = CreateRsaCertificate(),
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication succeeds when matching key is found among multiple JWKS entries.
    /// Tests key lookup with multiple registered keys.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingKeyAmongMultiple_ShouldReturnClient()
    {
        // Arrange
        var cert = CreateRsaCertificate();
        var certJwk = cert.ToJsonWebKey();
        var otherJwk1 = CreateRsaCertificate().ToJsonWebKey();
        var otherJwk2 = CreateEcdsaCertificate().ToJsonWebKey();

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(new[] { otherJwk1, certJwk, otherJwk2 }.ToAsyncEnumerable());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(client, result);
    }

    /// <summary>
    /// Verifies RSA keys with different modulus don't match.
    /// Tests RSA key comparison accuracy.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithDifferentRsaModulus_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateRsaCertificate();
        var certJwk = (RsaJsonWebKey)cert.ToJsonWebKey();

        var differentJwk = new RsaJsonWebKey
        {
            Modulus = new byte[certJwk.Modulus!.Length], // Different modulus
            Exponent = certJwk.Exponent,
        };

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(new[] { differentJwk }.ToAsyncEnumerable());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies ECDSA keys with different curve don't match.
    /// Tests ECDSA curve comparison.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithDifferentEcdsaCurve_ShouldReturnNull()
    {
        // Arrange
        var cert = CreateEcdsaCertificate(ECCurve.NamedCurves.nistP256);
        var differentCert = CreateEcdsaCertificate(ECCurve.NamedCurves.nistP384);
        var differentJwk = differentCert.ToJsonWebKey();

        var request = new ClientRequest
        {
            ClientId = "test-client",
            ClientCertificate = cert,
        };

        var client = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        };

        _clientInfoProviderMock
            .Setup(x => x.TryFindClientAsync("test-client"))
            .ReturnsAsync(client);

        _clientKeysProviderMock
            .Setup(x => x.GetSigningKeys(client))
            .Returns(new[] { differentJwk }.ToAsyncEnumerable());

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Creates a self-signed RSA certificate for testing.
    /// </summary>
    private static X509Certificate2 CreateRsaCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test Client",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));

        return certificate;
    }

    /// <summary>
    /// Creates a self-signed ECDSA certificate for testing.
    /// </summary>
    private static X509Certificate2 CreateEcdsaCertificate(ECCurve? curve = null)
    {
        using var ecdsa = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=Test Client",
            ecdsa,
            HashAlgorithmName.SHA256);

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));

        return certificate;
    }
}
