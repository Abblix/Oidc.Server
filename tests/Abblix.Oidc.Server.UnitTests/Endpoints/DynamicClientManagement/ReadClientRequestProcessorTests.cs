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
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// #30 regression: the RFC 7592 section 2.1/section 3 read response must carry the full registered metadata surface.
/// The processor previously omitted dpop_bound_access_tokens, authorization_details_types and the
/// token-exchange allowlists, so read diverged from the update response for the identical client.
/// </summary>
public class ReadClientRequestProcessorTests
{
    private const string TokenId = "jti-presented";

    private readonly Mock<IRegistrationAccessTokenService> _tokenService = new(MockBehavior.Loose);

    private ReadClientRequestProcessor CreateProcessor()
    {
        _tokenService
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");

        return new ReadClientRequestProcessor(_tokenService.Object, TimeProvider.System);
    }

    /// <summary>
    /// The token issued in reply carries the jti the request was authenticated with, never one read again from the
    /// store, which a rotation racing the read may have changed.
    /// </summary>
    [Fact]
    public async Task Read_IssuesTheTokenUnderTheJtiTheRequestWasAuthenticatedWith()
    {
        var processor = CreateProcessor();
        var request = new ValidClientRequest(new ClientRequest(), new ClientInfo("client-1"), TokenId);

        await processor.ProcessAsync(request);

        _tokenService.Verify(s => s.IssueTokenAsync(
            "client-1", It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), TokenId), Times.Once);
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
            TokenExchangeAllowedSubjectTokenTypes = [TokenExchangeTokenTypes.AccessToken],
            TokenExchangeAllowedAudiences = ["https://api.example.com"],
        };
        var request = new ValidClientRequest(new ClientRequest(), client, TokenId);

        // Act
        var result = await processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.True(response.DpopBoundAccessTokens);
        Assert.Equal(["payment_initiation"], response.AuthorizationDetailsTypes!);
        Assert.Equal(
            [TokenExchangeTokenTypes.AccessToken],
            response.TokenExchangeSubjectTokenTypes!);
        Assert.Equal(["https://api.example.com"], response.TokenExchangeAudiences!);
    }
}
