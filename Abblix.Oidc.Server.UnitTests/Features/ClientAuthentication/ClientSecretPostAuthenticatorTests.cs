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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="ClientSecretPostAuthenticator"/> verifying the client_secret_post authentication method
/// as defined in RFC 6749 section 2.3.1.
/// Tests cover credential extraction from request body, validation, and various error conditions.
/// </summary>
public class ClientSecretPostAuthenticatorTests : ClientAuthenticatorTestsBase<ClientSecretPostAuthenticator>
{
    protected override string ExpectedAuthenticationMethod => ClientAuthenticationMethods.ClientSecretPost;

    protected override ClientSecretPostAuthenticator CreateAuthenticator(
        Mock<IClientInfoProvider> clientInfoProvider,
        TimeProvider? timeProvider = null)
    {
        LicenseTestHelper.StartTest();

        var logger = new Mock<ILogger<ClientSecretPostAuthenticator>>();
        var hashService = new HashService();

        return new ClientSecretPostAuthenticator(
            logger.Object,
            clientInfoProvider.Object,
            timeProvider ?? TimeProvider.System,
            hashService);
    }

    protected override ClientRequest PrepareValidRequest(string clientId, string clientSecret)
    {
        return new ClientRequest
        {
            ClientId = clientId,
            ClientSecret = clientSecret
        };
    }

    protected override ClientRequest PrepareMissingPrimaryCredentialRequest()
    {
        // Missing client_id is considered the primary credential for Post method
        return new ClientRequest
        {
            ClientSecret = ClientSecret
        };
    }

    protected override ClientRequest PrepareWrongFormatRequest()
    {
        // For Post method, there's no "wrong format" per se - it's either present or not
        // Return missing both credentials to simulate wrong format
        return new ClientRequest();
    }

    protected override ClientRequest PrepareEmptyClientIdRequest()
    {
        return new ClientRequest
        {
            ClientId = string.Empty,
            ClientSecret = ClientSecret
        };
    }

    protected override ClientRequest PrepareEmptyClientSecretRequest()
    {
        return new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = string.Empty
        };
    }

    protected override ClientRequest PrepareWhitespaceClientIdRequest()
    {
        return new ClientRequest
        {
            ClientId = "   ",
            ClientSecret = ClientSecret
        };
    }
}
