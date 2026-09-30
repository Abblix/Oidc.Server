// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// A registration (RFC 7591) answers with what the store now holds, so one the store did not keep - raced by another
/// under the same id, or under an id the settings came to configure - is refused as a taken id is, and issues no
/// credentials.
/// </summary>
public class RegisterClientRequestProcessorTests
{
    private readonly Mock<IClientInfoManager> _clients = new(MockBehavior.Strict);
    private readonly Mock<IRegistrationAccessTokenService> _tokens = new(MockBehavior.Loose);

    private RegisterClientRequestProcessor Processor()
    {
        var credentials = new Mock<IClientCredentialFactory>(MockBehavior.Strict);
        credentials
            .Setup(c => c.Create(It.IsAny<string>(), "client-1"))
            .Returns(new ClientCredentials("client-1", "secret", null, null));

        var tokenIds = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIds.Setup(g => g.GenerateTokenId()).Returns("jti-1");

        _tokens
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");

        return new RegisterClientRequestProcessor(
            credentials.Object, _clients.Object, TimeProvider.System, tokenIds.Object, _tokens.Object);
    }

    private static ValidClientRegistrationRequest Request() => new(
        new ClientRegistrationRequest
        {
            ClientId = "client-1",
            RedirectUris = [new Uri("https://client.example.com/cb")],
        },
        SectorIdentifier: null);

    [Fact]
    public async Task ARegistrationTheStoreKeeps_IsAnsweredWithItsToken()
    {
        _clients
            .Setup(c => c.TryAddClientAsync(It.Is<RegisteredClient>(r =>
                r.ClientInfo.ClientId == "client-1" && r.RegistrationAccessTokenId == "jti-1")))
            .ReturnsAsync(true);

        var result = await Processor().ProcessAsync(Request());

        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal("client-1", response.ClientId);
        _tokens.Verify(
            s => s.IssueTokenAsync("client-1", It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), "jti-1"),
            Times.Once);
    }

    [Fact]
    public async Task ARegistrationTheStoreDoesNotKeep_IsRefusedAndIssuesNothing()
    {
        _clients.Setup(c => c.TryAddClientAsync(It.IsAny<RegisteredClient>())).ReturnsAsync(false);

        var result = await Processor().ProcessAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        _tokens.Verify(
            s => s.IssueTokenAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()),
            Times.Never);
    }
}
