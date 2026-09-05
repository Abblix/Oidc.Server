// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// #30 regression: the RFC 7592 §2.1/§3 read response must carry the full registered metadata surface.
/// The processor previously omitted dpop_bound_access_tokens, authorization_details_types and the
/// token-exchange allowlists, so read diverged from the update response for the identical client.
/// </summary>
public class ReadClientRequestProcessorTests
{
    private static ReadClientRequestProcessor CreateProcessor()
    {
        var tokenService = new Mock<IRegistrationAccessTokenService>(MockBehavior.Loose);
        tokenService
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");

        var tokenStore = new Mock<IRegistrationAccessTokenStore>(MockBehavior.Loose);
        tokenStore
            .Setup(s => s.GetTokenIdAsync(It.IsAny<string>()))
            .ReturnsAsync("jti-1");

        var idGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Loose);

        return new ReadClientRequestProcessor(
            tokenService.Object, tokenStore.Object, idGenerator.Object, TimeProvider.System);
    }

    [Fact]
    public async Task Read_ResponseEchoesDpopAuthorizationDetailsAndTokenExchangeAllowlists()
    {
        // Arrange
        var processor = CreateProcessor();
        var client = new ClientInfo("client-1")
        {
            RedirectUris = [new Uri("https://client.example.com/cb")],
            RequireDPoP = true,
            AuthorizationDetailsTypes = ["payment_initiation"],
            TokenExchangeAllowedSubjectTokenTypes = ["urn:ietf:params:oauth:token-type:access_token"],
            TokenExchangeAllowedAudiences = ["https://api.example.com"],
        };
        var request = new ValidClientRequest(new ClientRequest(), client);

        // Act
        var result = await processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.True(response.DpopBoundAccessTokens);
        Assert.Equal(["payment_initiation"], response.AuthorizationDetailsTypes!);
        Assert.Equal(
            ["urn:ietf:params:oauth:token-type:access_token"],
            response.TokenExchangeSubjectTokenTypes!);
        Assert.Equal(["https://api.example.com"], response.TokenExchangeAudiences!);
    }
}
