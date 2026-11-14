// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="ClientSecretBasicAuthenticator"/> verifying the client_secret_basic authentication method
/// as defined in RFC 7617.
/// Tests cover credential extraction from Authorization header with Basic scheme, Base64 decoding, validation,
/// and various error conditions.
/// </summary>
public class ClientSecretBasicAuthenticatorTests : ClientAuthenticatorTestsBase<ClientSecretBasicAuthenticator>
{
    protected override string ExpectedAuthenticationMethod => ClientAuthenticationMethods.ClientSecretBasic;

    protected override ClientSecretBasicAuthenticator CreateAuthenticator(
        Mock<IClientInfoProvider> clientInfoProvider,
        TimeProvider? timeProvider = null)
    {
        var logger = new Mock<ILogger<ClientSecretBasicAuthenticator>>();
        var hashService = new HashService();

        return new ClientSecretBasicAuthenticator(
            logger.Object,
            clientInfoProvider.Object,
            timeProvider ?? TimeProvider.System,
            hashService);
    }

    protected override ClientRequest PrepareValidRequest(string clientId, string clientSecret)
    {
        var credentials = $"{clientId}:{clientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic, base64Credentials).ToString()]
        };
    }

    /// <summary>
    /// RFC 9110 section 11.1 identifies the scheme by a case-insensitive token, so credentials under the Basic scheme
    /// in another case authenticate the client the same way.
    /// </summary>
    [Fact]
    public async Task ValidAuthentication_UnderTheSchemeInAnotherCase_ShouldAuthenticate()
    {
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(CreateClientInfo(ClientSecret));
        var valid = PrepareValidRequest(ClientId, ClientSecret);
        var request = valid with
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(
                TokenTypes.Basic.ToLowerInvariant(),
                valid.AuthorizationHeader!.Parameter).ToString()],
        };

        var result = await CreateAuthenticator(clientInfoProvider).TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(ClientId, result.GetSuccess().ClientId);
    }

    protected override ClientRequest PrepareMissingPrimaryCredentialRequest()
    {
        return new ClientRequest();
    }

    /// <summary>
    /// Credentials that are not base64 are the client's malformed request, not a fault of the server: the client is
    /// simply not authenticated by this method, so the caller answers invalid_client (RFC 6749 section 5.2).
    /// </summary>
    [Fact]
    public async Task CredentialsThatAreNotBase64_AreNotAuthenticated()
    {
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var request = new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic, "not*base64!").ToString()],
        };

        var result = await CreateAuthenticator(clientInfoProvider).TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        Assert.False(result.TryGetSuccess(out _));
    }

    protected override ClientRequest PrepareWrongFormatRequest()
    {
        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Bearer, base64Credentials).ToString()]
        };
    }

    protected override ClientRequest PrepareEmptyClientIdRequest()
    {
        var credentials = $":{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic, base64Credentials).ToString()]
        };
    }

    protected override ClientRequest PrepareEmptyClientSecretRequest()
    {
        var credentials = $"{ClientId}:";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic, base64Credentials).ToString()]
        };
    }

    protected override ClientRequest PrepareWhitespaceClientIdRequest()
    {
        var credentials = $"   :{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic, base64Credentials).ToString()]
        };
    }

    // ==================== BASIC-SPECIFIC TESTS ====================

    /// <summary>
    /// Verifies that authentication fails when the Authorization header parameter is missing.
    /// The Basic scheme requires credentials parameter.
    /// </summary>
    [Fact]
    public async Task MissingCredentialsParameter_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);
        var request = new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic).ToString()]
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.False(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies that authentication fails when credentials don't contain colon separator.
    /// According to RFC 7617, the format must be "user-id:password".
    /// </summary>
    [Fact]
    public async Task CredentialsWithoutColon_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        var credentials = $"{ClientId}{ClientSecret}"; // No colon
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic, base64Credentials).ToString()]
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.False(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// An Authorization header of another scheme, or one that does not parse, is still an attempt to authenticate
    /// through the header, which RFC 6749 section 5.2 answers with 401: a credential presented and refused.
    /// </summary>
    [Theory]
    [InlineData("Bearer abc")]
    [InlineData("Basic ,")]
    public async Task AnAuthorizationHeaderThisMethodCannotRead_IsAPresentedCredentialRefused(string line)
    {
        var authenticator = CreateAuthenticator(new Mock<IClientInfoProvider>(MockBehavior.Strict));

        var result = await authenticator.TryAuthenticateClientAsync(
            SingleIssuer.Tenant, new ClientRequest { AuthorizationHeaderLines = [line] });

        Assert.True(result.TryGetFailure(out var failure));
        Assert.IsNotType<UnauthenticatedCallerError>(failure);
        Assert.Equal(ErrorCodes.InvalidClient, failure.Error);
    }
}
