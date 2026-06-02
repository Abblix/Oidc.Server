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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Verifies that an RFC 7592 client update (a full replacement) re-persists the per-client scope
/// set. Dropping AllowedScopes on update would revert the client to "any scope" (null = unrestricted),
/// defeating the scope enforcement applied at the authorization and token endpoints.
/// </summary>
public class UpdateClientRequestProcessorTests
{
    [Fact]
    public async Task Update_PreservesAllowedScopes()
    {
        // Arrange
        ClientInfo? saved = null;
        var clientInfoManager = new Mock<IClientInfoManager>(MockBehavior.Strict);
        clientInfoManager
            .Setup(m => m.UpdateClientAsync(It.IsAny<ClientInfo>()))
            .Callback<ClientInfo>(c => saved = c)
            .Returns(Task.CompletedTask);

        var tokenService = new Mock<IRegistrationAccessTokenService>(MockBehavior.Loose);
        tokenService
            .Setup(s => s.IssueTokenAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>()))
            .ReturnsAsync("registration-access-token");

        var processor = new UpdateClientRequestProcessor(
            clientInfoManager.Object, tokenService.Object, TimeProvider.System);

        var model = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri("https://client.example.com/cb")],
            Scope = ["openid", "profile"],
        };
        var existing = new ClientInfo("client-1");
        var request = new ValidUpdateClientRequest(
            new UpdateClientRequest(new ClientRequest(), model), existing, model);

        // Act
        await processor.ProcessAsync(request);

        // Assert
        Assert.NotNull(saved);
        Assert.Equal(model.Scope, saved.AllowedScopes);
    }
}
