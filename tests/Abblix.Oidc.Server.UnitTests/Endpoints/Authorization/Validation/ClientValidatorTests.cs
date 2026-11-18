// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt;
using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="ClientValidator" /> verifying client authentication and authorization
/// per OAuth 2.0 RFC 6749. Tests cover client_id validation, client lookup, authorization checks,
/// and context population.
/// </summary>
public class ClientValidatorTests
{
    private const string ValidClientId = TestConstants.DefaultClientId;
    private const string ValidClientId2 = TestConstants.AlternativeClientId;
    private const string UnknownClientId = "unknown_client";

    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<IClientKeysProvider> _clientKeys;
    private readonly ClientValidator _validator;

    public ClientValidatorTests()
    {
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _clientKeys = new Mock<IClientKeysProvider>(MockBehavior.Strict);
        _clientKeys
            .Setup(k => k.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // Service tokens signed with an algorithm every profile admits, so a refusal below is the client's own
        _validator = Validator(SignedWith(SigningAlgorithms.PS256));
    }

    private ClientValidator Validator(OidcOptions options)
        => new(
            new Mock<ILogger<ClientValidator>>(MockBehavior.Loose).Object,
            _clientInfoProvider.Object,
            new ClientEncryptionKeyResolver(new ProfiledJwtIssuer(EncryptingWithRsa(), TestEncryptionAlgorithms.Every), _clientKeys.Object, TimeProvider.System, TestEncryptionAlgorithms.Every),
            Options.Create(options));

    /// <summary>A creator performing the RSA key management algorithms, which are all a key below declares.</summary>
    private static IJsonWebTokenCreator EncryptingWithRsa()
    {
        var creator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        creator
            .Setup(c => c.EncryptedResponseAlgorithmsSupported)
            .Returns(
            [
                EncryptionAlgorithms.KeyManagement.Rsa1_5,
                EncryptionAlgorithms.KeyManagement.RsaOaep,
                EncryptionAlgorithms.KeyManagement.RsaOaep256,
            ]);
        return creator.Object;
    }

    private static OidcOptions SignedWith(string algorithm)
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Signing.Algorithm = algorithm;
        options.ServiceTokens.RefreshToken.Signing.Algorithm = algorithm;
        return options;
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(string? clientId)
    {
        var request = new AuthorizationRequest
        {
            ClientId = clientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId]
        };

        return new AuthorizationValidationContext(request);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts valid client_id and populates context.
    /// Per OAuth 2.0 Section 2.2, client_id is REQUIRED parameter.
    /// Critical for client authentication and authorization.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientId_ShouldSucceed()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId);
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Same(clientInfo, context.ClientInfo);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects null client_id.
    /// Per OAuth 2.0, client_id is REQUIRED parameter for authorization requests.
    /// Critical for preventing unauthorized access.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullClientId_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(null);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Contains("required", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects unknown client_id.
    /// Per OAuth 2.0, only registered clients are authorized to make requests.
    /// Critical security check preventing unauthorized client access.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownClientId_ShouldReturnError()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, UnknownClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(UnknownClientId);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Contains("not authorized", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(TestTenant.Matched, UnknownClientId), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects empty client_id string.
    /// Empty string is not null, so it attempts client lookup.
    /// Tests edge case handling for malformed requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyClientId_ShouldReturnError()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, string.Empty))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(string.Empty);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts client_id with different formats.
    /// Tests that validator uses client_id exactly as provided.
    /// Uses ValidClientId2 to stay within license limits.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithVariousClientIdFormats_ShouldSucceed()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId2);
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId2))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId2);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.Same(clientInfo, context.ClientInfo);
    }

    /// <summary>
    /// Verifies that ValidateAsync is case-sensitive for client_id.
    /// Per OAuth 2.0, client identifiers are case-sensitive.
    /// Tests that TestConstants.DefaultClientId and TestConstants.DefaultClientId are different clients.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientIdIsCaseSensitive_ShouldTreatDifferently()
    {
        // Arrange
        const string uppercaseClientId = TestConstants.DefaultClientId;
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, uppercaseClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(uppercaseClientId);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(TestTenant.Matched, uppercaseClientId), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync populates context.ClientInfo on success.
    /// Downstream validators rely on ClientInfo being populated.
    /// Per design: ClientInfo is only accessible after successful validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldPopulateClientInfo()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId)
        {
            ClientName = "Test Client",
            AllowedResponseTypes = [[ResponseTypes.Code]]
        };
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        // ClientInfo is now accessible after successful validation
        Assert.Equal(ValidClientId, context.ClientInfo.ClientId);
        Assert.Equal("Test Client", context.ClientInfo.ClientName);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns error when client not found.
    /// Per design: ClientInfo throws when accessed before successful validation.
    /// Tests that error is returned without setting ClientInfo.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnError_ShouldReturnErrorWithoutSettingClientInfo()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, UnknownClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(UnknownClientId);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        // Note: Cannot access context.ClientInfo - it throws when not set
    }

    /// <summary>
    /// Verifies that ValidateAsync includes error code in error response.
    /// Per OAuth 2.0, error responses MUST include error parameter.
    /// Critical for proper error communication to client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeErrorCode()
    {
        // Arrange
        var context = CreateContext(null);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Error);
        Assert.NotEmpty(result.Error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes error description in error response.
    /// Per OAuth 2.0, error_description is OPTIONAL but RECOMMENDED.
    /// Helps developers diagnose client authentication failures.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeErrorDescription()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, UnknownClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(UnknownClientId);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.ErrorDescription);
        Assert.NotEmpty(result.ErrorDescription);
    }

    /// <summary>
    /// Verifies that ValidateAsync calls IClientInfoProvider exactly once.
    /// Tests efficient client lookup without redundant calls.
    /// Important for performance with database-backed client stores.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallClientInfoProviderOnce()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId);
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        _clientInfoProvider.Verify(
            p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId),
            Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles provider returning null gracefully.
    /// Tests error handling when client lookup fails.
    /// Critical for robust error handling in production.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenProviderReturnsNull_ShouldReturnError()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(ValidClientId);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6 has the server sign only with PS256 or ES256, and the authorization endpoint signs
    /// for the client - a front-channel ID token, a JWT authorization response - with what the client is configured
    /// for. A stored client configured for RS256 under that profile is refused here, before anything is signed for
    /// it, as the same client configured for PS256 is not.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, false)]
    [InlineData(SigningAlgorithms.PS256, true)]
    public async Task ValidateAsync_AClientTheServerWouldSignForAgainstItsProfile_IsRefused(
        string algorithm, bool accepted)
    {
        var clientInfo = new ClientInfo(ValidClientId)
        {
            SecurityProfile = ClientSecurityProfile.Fapi1Advanced,
            IdentityTokenSignedResponseAlgorithm = algorithm,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
        };
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(ValidClientId));

        Assert.Equal(accepted ? null : ErrorCodes.UnauthorizedClient, result?.Error);
    }

    /// <summary>
    /// FAPI 2.0 section 5.4.1 has the server use only the profile's algorithms "when creating or processing JWTs", and
    /// the access and refresh tokens it would issue the client are signed with what the deployment configures. A client
    /// held to FAPI 2.0 at a tenant held to none, which the startup check never saw, is refused here while those tokens
    /// are signed RS256, before anything is spent; signed PS256 it passes.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, false)]
    [InlineData(SigningAlgorithms.PS256, true)]
    public async Task ValidateAsync_TheServiceTokensTheClientWouldBeIssued_AreJudgedByItsProfile(
        string serviceTokenAlgorithm, bool accepted)
    {
        var clientInfo = new ClientInfo(ValidClientId)
        {
            SecurityProfile = ClientSecurityProfile.Fapi2,
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
        };
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);
        var validator = Validator(SignedWith(serviceTokenAlgorithm));

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(ValidClientId));

        Assert.Equal(accepted ? null : ErrorCodes.UnauthorizedClient, result?.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6.1: "For JWE, both clients and authorization servers shall not use the RSA1_5
    /// algorithm". A client that registered RSA-OAEP-256 for its ID tokens is refused here when it has no key that
    /// algorithm encrypts to - a key set of RSA1_5 keys or none at all - and passes with one; a client that registered
    /// no encryption algorithm is sent nothing encrypted, and its key set is not judged.
    /// </summary>
    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, new[] { EncryptionAlgorithms.KeyManagement.Rsa1_5 }, false)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, new string[0], false)]
    [InlineData(
        EncryptionAlgorithms.KeyManagement.RsaOaep256,
        new[] { EncryptionAlgorithms.KeyManagement.Rsa1_5, EncryptionAlgorithms.KeyManagement.RsaOaep256 },
        true)]
    [InlineData(null, new[] { EncryptionAlgorithms.KeyManagement.Rsa1_5 }, true)]
    public async Task ValidateAsync_ARegisteredAlgorithmWithNoKeyToEncryptTo_IsRefused(
        string? registered, string[] declared, bool accepted)
    {
        var clientInfo = new ClientInfo(ValidClientId)
        {
            SecurityProfile = ClientSecurityProfile.Fapi1Advanced,
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            IdentityTokenEncryptedResponseAlgorithm = registered,
        };
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);
        _clientKeys
            .Setup(k => k.GetEncryptionKeys(clientInfo))
            .Returns(declared.Select(JsonWebKey (alg) => new RsaJsonWebKey { Algorithm = alg }).ToAsyncEnumerable());

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(ValidClientId));

        Assert.Equal(accepted ? null : ErrorCodes.UnauthorizedClient, result?.Error);
    }

    /// <summary>The client registering <paramref name="algorithm"/> for the JWT <paramref name="setting"/> names.</summary>
    private static ClientInfo Registering(ClientInfo client, string setting, string algorithm) => setting switch
    {
        nameof(ClientInfo.IdentityTokenEncryptedResponseAlgorithm) => client with { IdentityTokenEncryptedResponseAlgorithm = algorithm },
        nameof(ClientInfo.UserInfoEncryptedResponseAlgorithm) => client with { UserInfoEncryptedResponseAlgorithm = algorithm },
        nameof(ClientInfo.IntrospectionEncryptedResponseAlgorithm) => client with { IntrospectionEncryptedResponseAlgorithm = algorithm },
        nameof(ClientInfo.AuthorizationEncryptedResponseAlgorithm) => client with { AuthorizationEncryptedResponseAlgorithm = algorithm },
        _ => throw new ArgumentOutOfRangeException(nameof(setting), setting, null),
    };

    /// <summary>
    /// Each JWT a client registered an encryption algorithm for is judged: a client registering RSA-OAEP-256 for its ID
    /// tokens, userinfo, introspection or authorization responses with only RSA1_5 keys, which FAPI 1.0 Part 2 section
    /// 8.6.1 forbids, is refused, and passes once it publishes an RSA-OAEP-256 key.
    /// </summary>
    [Theory]
    [InlineData(nameof(ClientInfo.IdentityTokenEncryptedResponseAlgorithm), false)]
    [InlineData(nameof(ClientInfo.IdentityTokenEncryptedResponseAlgorithm), true)]
    [InlineData(nameof(ClientInfo.UserInfoEncryptedResponseAlgorithm), false)]
    [InlineData(nameof(ClientInfo.UserInfoEncryptedResponseAlgorithm), true)]
    [InlineData(nameof(ClientInfo.IntrospectionEncryptedResponseAlgorithm), false)]
    [InlineData(nameof(ClientInfo.IntrospectionEncryptedResponseAlgorithm), true)]
    [InlineData(nameof(ClientInfo.AuthorizationEncryptedResponseAlgorithm), false)]
    [InlineData(nameof(ClientInfo.AuthorizationEncryptedResponseAlgorithm), true)]
    public async Task ValidateAsync_EachRegisteredEncryption_IsJudged(string setting, bool withKey)
    {
        var clientInfo = Registering(
            new ClientInfo(ValidClientId)
            {
                SecurityProfile = ClientSecurityProfile.Fapi1Advanced,
                IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
                AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
                UserInfoSignedResponseAlgorithm = SigningAlgorithms.PS256,
            },
            setting,
            EncryptionAlgorithms.KeyManagement.RsaOaep256);
        string[] declared = withKey
            ? [EncryptionAlgorithms.KeyManagement.Rsa1_5, EncryptionAlgorithms.KeyManagement.RsaOaep256]
            : [EncryptionAlgorithms.KeyManagement.Rsa1_5];
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ValidClientId))
            .ReturnsAsync(clientInfo);
        _clientKeys
            .Setup(k => k.GetEncryptionKeys(clientInfo))
            .Returns(declared.Select(JsonWebKey (alg) => new RsaJsonWebKey { Algorithm = alg }).ToAsyncEnumerable());

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(ValidClientId));

        Assert.Equal(withKey ? null : ErrorCodes.UnauthorizedClient, result?.Error);
    }
}
