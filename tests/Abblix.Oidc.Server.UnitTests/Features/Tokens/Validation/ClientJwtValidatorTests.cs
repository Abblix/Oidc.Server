// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// Unit tests for <see cref="ClientJwtValidator"/> verifying JWT validation for client-issued tokens.
/// Tests cover client authentication JWTs and request objects per RFC 7523 (JWT Bearer Token),
/// RFC 9101 (JWT-Secured Authorization Request), and OpenID Connect Core Section 9 (Client Authentication).
/// </summary>
public class ClientJwtValidatorTests
{
    private const string ValidClientId = TestConstants.DefaultClientId;
    private const string AnotherClientId = "client_456";
    private const string RequestUri = "https://auth.example.com/token";
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;
    private const string ValidJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGllbnRfMTIzIn0.signature";

    private readonly Mock<IJsonWebTokenValidator> _tokenValidator;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<IClientKeysProvider> _clientKeysProvider;
    private readonly Mock<IAuthServiceKeysProvider> _serviceKeysProvider;
    private readonly JsonWebKey _serverDecryptionKey;
    private readonly ClientJwtValidator _validator;

    public ClientJwtValidatorTests()
    {
        var logger = new Mock<ILogger<ClientJwtValidator>>();
        var requestInfoProvider = new Mock<IRequestInfoProvider>(MockBehavior.Strict);
        _tokenValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _clientKeysProvider = new Mock<IClientKeysProvider>(MockBehavior.Strict);
        _serviceKeysProvider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        _serverDecryptionKey = new RsaJsonWebKey { KeyId = "server-enc" };
        _serviceKeysProvider
            .Setup(p => p.GetEncryptionKeys(TestTenant.Matched, true))
            .Returns(new[] { _serverDecryptionKey }.ToAsyncEnumerable());

        requestInfoProvider.Setup(p => p.RequestUri).Returns(new Uri(RequestUri));

        _validator = new ClientJwtValidator(
            logger.Object,
            requestInfoProvider.Object,
            new ProfiledJwtValidator(_tokenValidator.Object),
            _clientInfoProvider.Object,
            _clientKeysProvider.Object,
            _serviceKeysProvider.Object,
            TimeProvider.System);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when audience matches the request URI.
    /// Per RFC 7523 Section 3, audience must identify the authorization server (token endpoint).
    /// Critical for preventing token misuse - ensures client JWT is intended for this server.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMatchingAudience_ShouldReturnSuccess()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback accepts request URI
        var audienceValidationResult = await capturedParams.ValidateAudience!([RequestUri]);
        Assert.True(audienceValidationResult);
    }

    /// <summary>
    /// The keys read again on an unfamiliar kid (OpenID Connect Core 1.0 section 10.1.1) are the client's own, asked
    /// for past the copy held, while the keys first returned come from the copy.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReadsTheClientsKeysAgainOnlyForTheRefetch()
    {
        var clientInfo = CreateClientInfo(ValidClientId);
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                await p.ResolveIssuerSigningKeys!(ValidClientId).ToArrayAsync();
                await p.RefetchIssuerSigningKeys!(ValidClientId).ToArrayAsync();
                return CreateValidToken();
            });
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);
        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo, It.IsAny<bool>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        _clientKeysProvider.Verify(p => p.GetSigningKeys(clientInfo, false), Times.Once);
        _clientKeysProvider.Verify(p => p.GetSigningKeys(clientInfo, true), Times.Once);
    }

    /// <summary>
    /// The token types the caller accepts reach the JWT validator unchanged, which is what refuses a token of
    /// another type.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PassesTheAcceptedTokenTypes()
    {
        var accepted = TokenTypePolicy.Exactly(JsonWebTokenTypes.ClientAuthentication);
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return CreateValidToken();
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, accepted);

        Assert.NotNull(capturedParams);
        Assert.Same(accepted, capturedParams.TokenTypes);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when audience matches the issuer identifier.
    /// Per RFC 7523 Section 3 and OpenID Connect Core 1.0 Section 9, the authorization server's
    /// issuer identifier is an acceptable audience value in addition to the token endpoint URL.
    /// This ensures compatibility with clients that use the issuer ID as the audience.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIssuerAsAudience_ShouldReturnSuccess()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback accepts issuer identifier
        var audienceValidationResult = await capturedParams.ValidateAudience!([Issuer]);
        Assert.True(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT when audience matches neither request URI nor issuer.
    /// Prevents token substitution attacks where client JWT from one server is used on another.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNonMatchingAudience_ShouldRejectToken()
    {
        // Arrange
        const string wrongAudience = "https://different-server.com/token";

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return new JwtValidationError(JwtError.InvalidToken, "Invalid audience");
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation callback rejects wrong audience
        var audienceValidationResult = await capturedParams.ValidateAudience!([wrongAudience]);
        Assert.False(audienceValidationResult);
    }

    /// <summary>
    /// The audience is compared with the request address as written, as RFC 7519 section 4.1.3 compares
    /// StringOrURI values, so a spelling of the same address in another case or with its default port is refused.
    /// </summary>
    [Theory]
    [InlineData("https://AUTH.example.com/token")]
    [InlineData("HTTPS://auth.example.com/token")]
    [InlineData("https://auth.example.com:443/token")]
    public async Task ValidateAsync_TheRequestAddressSpelledOtherwise_IsRefused(string audience)
    {
        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => capturedParams = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid audience"));

        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        Assert.False(await capturedParams!.ValidateAudience!([audience]));
        Assert.True(await capturedParams.ValidateAudience([RequestUri]));
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when one of multiple audiences matches request URI.
    /// Per RFC 7519 Section 4.1.3, audience can be array - validation passes if any value matches.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAudiencesOneMatching_ShouldReturnSuccess()
    {
        // Arrange
        var audiences = new[] { "https://other.com", RequestUri, "https://another.com" };
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation accepts when one matches
        var audienceValidationResult = await capturedParams.ValidateAudience!(audiences);
        Assert.True(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT when empty audience collection provided.
    /// Per RFC 7519, audience is required for client authentication tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyAudience_ShouldRejectToken()
    {
        // Arrange
        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return new JwtValidationError(JwtError.InvalidToken, "Audience is empty");
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);

        // Verify audience validation rejects empty collection
        var audienceValidationResult = await capturedParams.ValidateAudience!([]);
        Assert.False(audienceValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts JWT when issuer matches a known client ID.
    /// Per RFC 7523 Section 3, issuer must be the client_id of the OAuth client.
    /// Critical for client authentication - proves client identity.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidIssuer_ShouldReturnSuccessAndClientInfo()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.True(result.TryGetSuccess(out var validToken));
        Assert.Same(clientInfo, validToken.Client);
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback
        var issuerValidationResult = await capturedParams.ValidateIssuer!(ValidClientId);
        Assert.True(issuerValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT when issuer does not match any known client.
    /// Prevents unauthorized clients from authenticating with forged JWTs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownIssuer_ShouldRejectToken()
    {
        // Arrange
        const string unknownIssuer = "unknown_client";

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(unknownIssuer);
                return new JwtValidationError(JwtError.InvalidToken, "Unknown issuer");
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, unknownIssuer))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.NotNull(capturedParams);

        // Verify issuer validation callback rejects unknown issuer
        var issuerValidationResult = await capturedParams.ValidateIssuer!(unknownIssuer);
        Assert.False(issuerValidationResult);
    }

    /// <summary>
    /// Verifies that ValidateAsync throws InvalidOperationException when attempting to validate
    /// different issuer after ClientInfo is already set.
    /// Prevents validator state corruption and ensures single-client-per-instance semantics.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentIssuerAfterClientInfoSet_ShouldReturnFalse()
    {
        // Arrange - First validation sets ClientInfo
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Act & Assert - Second validation with different issuer should throw
        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);
        Assert.NotNull(capturedParams);

        // Second call with different issuer should return false (already looked up different client)
        var result = await capturedParams.ValidateIssuer!(AnotherClientId);
        Assert.False(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts multiple validations with same issuer.
    /// Once ClientInfo is set, subsequent validations with same issuer should succeed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSameIssuerMultipleTimes_ShouldReturnSuccess()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act - Validate twice with same issuer
        var result1 = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);
        var result2 = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.True(result1.TryGetSuccess(out var validToken1));
        Assert.True(result2.TryGetSuccess(out var validToken2));
        Assert.Same(clientInfo, validToken1.Client);
        Assert.Same(clientInfo, validToken2.Client);

        // Verify client lookup happened twice (each ValidateAsync creates new ValidationContext)
        // The flag prevents duplicate calls within a single validation, not across validations
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId), Times.Exactly(2));
    }

    /// <summary>
    /// Verifies that when the inner JWT validation succeeds but no client can be determined - neither
    /// from the issuer nor from a client_id claim - ValidateAsync returns a failure rather than a
    /// ValidJsonWebToken with a null Client. Downstream callers (e.g. the request-object signing-alg
    /// pin) rely on Client being non-null on success.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenClientCannotBeDetermined_ShouldReturnFailure()
    {
        // Arrange - inner validation succeeds without resolving a client (ValidateIssuer is not
        // invoked here), and the token carries no client_id claim.
        var token = CreateValidToken();
        Assert.Null(token.Payload.ClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(token);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert - a failure, never a success carrying a null Client.
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync resolves signing keys from client keys provider.
    /// Per RFC 7523, client must sign JWT with private key; server validates with public key.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldResolveSigningKeysFromClientKeysProvider()
    {
        // Arrange
        var signingKey1 = new RsaJsonWebKey { KeyId = "client_key1", Algorithm = SigningAlgorithms.RS256 };
        var signingKey2 = new RsaJsonWebKey { KeyId = "client_key2", Algorithm = SigningAlgorithms.RS256 };
        var signingKeys = new[] { signingKey1, signingKey2 };

        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                // Simulate the validator calling ValidateIssuer
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(signingKeys.ToAsyncEnumerable());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams.ResolveIssuerSigningKeys!(ValidClientId).ToArrayAsync(TestContext.Current.CancellationToken);
        Assert.Equal(signingKeys.Length, resolvedKeys.Length);

        _clientKeysProvider.Verify(p => p.GetSigningKeys(clientInfo), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles scenario with no signing keys available.
    /// Tests that key resolution doesn't fail when provider returns empty collection.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoSigningKeys_ShouldReturnEmptyKeyCollection()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams.ResolveIssuerSigningKeys!(ValidClientId).ToArrayAsync(TestContext.Current.CancellationToken);
        Assert.Empty(resolvedKeys);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns empty key collection when issuer is invalid.
    /// Security safeguard - no keys should be provided for unknown clients.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidIssuerInKeyResolution_ShouldReturnEmptyKeyCollection()
    {
        // Arrange
        const string unknownIssuer = "unknown_client";

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(unknownIssuer);
                return new JwtValidationError(JwtError.InvalidToken, "Unknown issuer");
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, unknownIssuer))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        var resolvedKeys = await capturedParams.ResolveIssuerSigningKeys!(unknownIssuer).ToArrayAsync(TestContext.Current.CancellationToken);
        Assert.Empty(resolvedKeys);

        // Verify GetSigningKeys was never called for unknown client
        _clientKeysProvider.Verify(p => p.GetSigningKeys(It.IsAny<ClientInfo>()), Times.Never);
    }

    /// <summary>
    /// Verifies that ValidateAsync wires the server's own private keys as the token-decryption keys,
    /// so a request object that the client JWE-encrypted to the server can be decrypted (RFC 9101
    /// section 6.1). The inner signed JWT is still verified with the client's key.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldResolveServerDecryptionKeys()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert - the decryption-key resolver is configured and yields the server's private keys.
        Assert.NotNull(capturedParams);
        Assert.NotNull(capturedParams.ResolveTokenDecryptionKeys);
        var decryptionKeys = await capturedParams.ResolveTokenDecryptionKeys(string.Empty)
            .ToArrayAsync(TestContext.Current.CancellationToken);
        Assert.Contains(_serverDecryptionKey, decryptionKeys);
    }

    /// <summary>
    /// Verifies that ValidateAsync uses Default validation options when not specified.
    /// Default includes: ValidateIssuer, ValidateAudience, RequireSignedTokens, ValidateIssuerSigningKey, ValidateLifetime.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutOptions_ShouldUseDefaultOptions()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.Equal(ValidationOptions.Default, capturedParams.Options);
    }

    /// <summary>
    /// Verifies that ValidateAsync applies custom validation options.
    /// Tests that specified options are passed through to the underlying validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomOptions_ShouldApplyOptions()
    {
        // Arrange
        const ValidationOptions customOptions = ValidationOptions.ValidateIssuer | ValidationOptions.ValidateLifetime;

        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller, customOptions);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.Equal(customOptions, capturedParams.Options);
    }

    /// <summary>
    /// Verifies complete validation flow for a valid client-signed JWT.
    /// Tests that all validation steps pass for properly formed and signed client authentication token.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientJwt_ShouldReturnValidTokenAndClientInfo()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                // Simulate the validator calling ValidateIssuer
                await p.ValidateIssuer!(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.True(result.TryGetSuccess(out var validToken));
        Assert.Same(token, validToken.Token);
        Assert.Same(clientInfo, validToken.Client);

        _tokenValidator.Verify(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()), Times.Once);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects JWT with invalid signature.
    /// Per RFC 7515 Section 5.2, signature validation failure means token is not authentic.
    /// Critical for client authentication - ensures JWT was signed by legitimate client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidSignature_ShouldReturnError()
    {
        // Arrange
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid signature"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects expired JWT.
    /// Per RFC 7519 Section 4.1.4, exp claim defines token expiration - expired tokens are invalid.
    /// Prevents replay attacks with old client authentication tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExpiredToken_ShouldReturnError()
    {
        // Arrange
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Token expired"));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(CreateClientInfo(ValidClientId));

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync configures all validation parameters correctly.
    /// Tests that issuer validation, audience validation, and key resolution are all configured.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldConfigureAllValidationParameters()
    {
        // Arrange
        var token = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        ValidationParameters? capturedParams = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                capturedParams = p;
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return token;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.NotNull(capturedParams);
        Assert.NotNull(capturedParams.ValidateIssuer);
        Assert.NotNull(capturedParams.ValidateAudience);
        Assert.NotNull(capturedParams.ResolveIssuerSigningKeys);
        Assert.Equal(ValidationOptions.Default, capturedParams.Options);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns delegated validation result from underlying validator.
    /// Tests that the validator correctly passes through results.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldDelegateToUnderlyingValidator()
    {
        // Arrange
        var expectedToken = CreateValidToken();
        var clientInfo = CreateClientInfo(ValidClientId);

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                if (p.ValidateIssuer != null)
                    await p.ValidateIssuer(ValidClientId);
                return expectedToken;
            });

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
        _tokenValidator.Verify(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()), Times.Once);
    }

    private static JsonWebToken CreateValidToken()
    {
        return new JsonWebToken
        {
            Header =
            {
                Algorithm = SigningAlgorithms.RS256,
            },
            Payload =
            {
                Issuer = ValidClientId,
                Audiences = [RequestUri],
                Subject = ValidClientId,
                IssuedAt = TimeProvider.System.GetUtcNow(),
                ExpiresAt = TimeProvider.System.GetUtcNow().AddMinutes(5),
                NotBefore = TimeProvider.System.GetUtcNow(),
            }
        };
    }

    private static ClientInfo CreateClientInfo(string clientId)
    {
        return new ClientInfo(clientId)
        {
            ClientSecrets = [],
        };
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6 has the server use "PS256 or ES256", so what a client held to FAPI 1.0 Advanced
    /// signs for it - a request object, an authentication assertion - is refused under any other algorithm once the
    /// client is known; PS256 and ES256 pass, and a client held to no profile keeps RS256.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, SigningAlgorithms.RS256, false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, SigningAlgorithms.PS256, true)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, SigningAlgorithms.ES256, true)]
    [InlineData(ClientSecurityProfile.Fapi2, SigningAlgorithms.RS256, false)]
    [InlineData(ClientSecurityProfile.Fapi2, SigningAlgorithms.ES256, true)]
    [InlineData(null, SigningAlgorithms.RS256, true)]
    public async Task ValidateAsync_TheClientsProfile_DecidesTheSignatureAlgorithm(
        ClientSecurityProfile? profile, string algorithm, bool accepted)
    {
        var token = CreateValidToken();
        token.Header.Algorithm = algorithm;
        var clientInfo = CreateClientInfo(ValidClientId);
        clientInfo.SecurityProfile = profile;

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                await p.ValidateIssuer!(ValidClientId);
                return token;
            });
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    /// <summary>
    /// What a client encrypts for the server is judged by the same clause: a request object encrypted with RSA1_5 by
    /// a client held to FAPI 1.0 Advanced is refused once the client is known, the same object encrypted with
    /// RSA-OAEP-256 passes, and a client held to no profile keeps RSA1_5.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, EncryptionAlgorithms.KeyManagement.Rsa1_5, false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, EncryptionAlgorithms.KeyManagement.RsaOaep256, true)]
    [InlineData(null, EncryptionAlgorithms.KeyManagement.Rsa1_5, true)]
    public async Task ValidateAsync_TheClientsProfile_DecidesTheKeyManagementAlgorithm(
        ClientSecurityProfile? profile, string keyManagement, bool accepted)
    {
        const string jwe = "header.key.iv.ciphertext.tag";
        var token = CreateValidToken();
        token.Header.Algorithm = SigningAlgorithms.PS256;
        var clientInfo = CreateClientInfo(ValidClientId);
        clientInfo.SecurityProfile = profile;

        // The validator reports each JWE layer's key management algorithm before decrypting it, as the real one does
        _tokenValidator
            .Setup(v => v.ValidateAsync(jwe, It.IsAny<ValidationParameters>()))
            .Returns(async (string _, ValidationParameters p) =>
            {
                if (!p.ValidateKeyManagementAlgorithm!(keyManagement))
                    return new JwtValidationError(JwtError.InvalidToken, "refused");

                await p.ValidateIssuer!(ValidClientId);
                return token;
            });
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, null, jwe, TokenTypePolicy.CheckedByCaller);

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Under a tenant holding every client to FAPI 1.0 Advanced a layer encrypted with RSA1_5 is refused before it is
    /// decrypted, the client not yet known; RSA-OAEP-256 is let through.
    /// </summary>
    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5, false)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, true)]
    public async Task ValidateAsync_TheTenantsProfile_JudgesEachLayerBeforeDecryption(string keyManagement, bool admitted)
    {
        ValidationParameters? parameters = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns((string _, ValidationParameters p) =>
            {
                parameters = p;
                return Task.FromResult<Abblix.Utils.Result<JsonWebToken, JwtValidationError>>(
                    new JwtValidationError(JwtError.InvalidToken, "not under test"));
            });
        var tenant = new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced }.ToTenant();

        await _validator.ValidateAsync(tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        Assert.Equal(admitted, parameters!.ValidateKeyManagementAlgorithm!(keyManagement));
    }

    /// <summary>
    /// Where the request names its client outside the token, as an authorization request names it in client_id, that
    /// client's profile bounds every layer before it is decrypted: a request object encrypted with RSA1_5 by a client
    /// held to FAPI 1.0 Advanced is refused unread at a tenant held to none (Part 2 section 8.6.1), while one with no
    /// client named is left to the tenant's profile until the token names its client.
    /// </summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task ValidateAsync_TheNamedClientsProfile_JudgesEachLayerBeforeDecryption(bool named, bool admitted)
    {
        ValidationParameters? parameters = null;
        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns((string _, ValidationParameters p) =>
            {
                parameters = p;
                return Task.FromResult<Abblix.Utils.Result<JsonWebToken, JwtValidationError>>(
                    new JwtValidationError(JwtError.InvalidToken, "not under test"));
            });
        var client = CreateClientInfo(ValidClientId);
        client.SecurityProfile = ClientSecurityProfile.Fapi1Advanced;

        await _validator.ValidateAsync(
            SingleIssuer.Tenant, named ? client : null, ValidJwt, TokenTypePolicy.CheckedByCaller);

        Assert.Equal(
            admitted,
            parameters!.ValidateKeyManagementAlgorithm!(EncryptionAlgorithms.KeyManagement.Rsa1_5));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.9 "requires that jwks_uri endpoints shall be served over TLS": a client held to FAPI
    /// 1.0 Advanced whose jwks_uri is http is given no keys to verify with, so nothing it signs is accepted on any path,
    /// whatever schemes the host lets the fetcher use; an https jwks_uri is read.
    /// </summary>
    [Theory]
    [InlineData("http://client.example.com/jwks", false)]
    [InlineData("https://client.example.com/jwks", true)]
    public async Task ResolveIssuerSigningKeys_Fapi1Advanced_ReadsOnlyAnHttpsJwksUri(string jwksUri, bool read)
    {
        var clientInfo = CreateClientInfo(ValidClientId);
        clientInfo.SecurityProfile = ClientSecurityProfile.Fapi1Advanced;
        clientInfo.JwksUri = new Uri(jwksUri);
        var key = new RsaJsonWebKey { KeyId = "client-key" };
        ValidationParameters? parameters = null;

        _tokenValidator
            .Setup(v => v.ValidateAsync(ValidJwt, It.IsAny<ValidationParameters>()))
            .Returns((string _, ValidationParameters p) =>
            {
                parameters = p;
                return Task.FromResult<Abblix.Utils.Result<JsonWebToken, JwtValidationError>>(
                    new JwtValidationError(JwtError.InvalidToken, "not under test"));
            });
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);
        _clientKeysProvider
            .Setup(p => p.GetSigningKeys(clientInfo, false))
            .Returns(new JsonWebKey[] { key }.ToAsyncEnumerable());

        await _validator.ValidateAsync(SingleIssuer.Tenant, null, ValidJwt, TokenTypePolicy.CheckedByCaller);
        var keys = await parameters!.ResolveIssuerSigningKeys!(ValidClientId).ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.Equal(read ? 1 : 0, keys.Length);
    }
}
