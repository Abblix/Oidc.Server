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
        LicenseTestHelper.StartTest();

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
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };
    }

    protected override ClientRequest PrepareMissingPrimaryCredentialRequest()
    {
        return new ClientRequest();
    }

    protected override ClientRequest PrepareWrongFormatRequest()
    {
        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Bearer", base64Credentials)
        };
    }

    protected override ClientRequest PrepareEmptyClientIdRequest()
    {
        var credentials = $":{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };
    }

    protected override ClientRequest PrepareEmptyClientSecretRequest()
    {
        var credentials = $"{ClientId}:";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };
    }

    protected override ClientRequest PrepareWhitespaceClientIdRequest()
    {
        var credentials = $"   :{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        return new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
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
            AuthorizationHeader = new AuthenticationHeaderValue("Basic")
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
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
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }
}
