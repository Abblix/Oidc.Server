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
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Verifies RFC 7592 client-update behavior: the update (a full replacement) re-persists the
/// per-client scope set, and it rotates the registration access token's jti so previously issued
/// tokens are invalidated (RFC 7592 §5).
/// </summary>
public class UpdateClientRequestProcessorTests
{
    private static (UpdateClientRequestProcessor processor, Mock<IClientInfoManager> manager,
        Mock<IRegistrationAccessTokenService> tokenService, Mock<IRegistrationAccessTokenStore> tokenStore,
        Mock<ITokenIdGenerator> idGenerator)
        CreateProcessor(Action<ClientInfo> onSave)
    {
        var clientInfoManager = new Mock<IClientInfoManager>(MockBehavior.Strict);
        clientInfoManager
            .Setup(m => m.UpdateClientAsync(It.IsAny<ClientInfo>()))
            .Callback<ClientInfo>(onSave)
            .Returns(Task.CompletedTask);

        var tokenService = new Mock<IRegistrationAccessTokenService>(MockBehavior.Loose);
        tokenService
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");

        var tokenStore = new Mock<IRegistrationAccessTokenStore>(MockBehavior.Loose);
        var idGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);

        var processor = new UpdateClientRequestProcessor(
            clientInfoManager.Object, tokenService.Object, tokenStore.Object, idGenerator.Object, TimeProvider.System);

        return (processor, clientInfoManager, tokenService, tokenStore, idGenerator);
    }

    [Fact]
    public async Task Update_PreservesAllowedScopes()
    {
        // Arrange
        ClientInfo? saved = null;
        var (processor, _, _, _, idGenerator) = CreateProcessor(c => saved = c);
        idGenerator.Setup(g => g.GenerateTokenId()).Returns("new-jti");

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

    /// <summary>
    /// Verifies the update rotates the registration access token jti: a freshly generated id is
    /// recorded in the binding store and embedded in the issued token. Because the validator binds
    /// the token to the stored jti, this invalidates every token issued before the update (RFC 7592 §5).
    /// </summary>
    [Fact]
    public async Task Update_RotatesRegistrationAccessTokenId()
    {
        // Arrange
        var (processor, _, tokenService, tokenStore, idGenerator) = CreateProcessor(_ => { });
        idGenerator.Setup(g => g.GenerateTokenId()).Returns("rotated-jti");

        var model = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri("https://client.example.com/cb")],
        };
        var existing = new ClientInfo("client-1");
        var request = new ValidUpdateClientRequest(
            new UpdateClientRequest(new ClientRequest(), model), existing, model);

        // Act
        await processor.ProcessAsync(request);

        // Assert
        tokenStore.Verify(s => s.SetTokenIdAsync("client-1", "rotated-jti"), Times.Once);
        tokenService.Verify(
            s => s.IssueTokenAsync("client-1", It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), "rotated-jti"),
            Times.Once);
    }
}
