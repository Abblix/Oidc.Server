// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

// Which subject tokens issued to another client a client exchanges, by its CrossClientSubjectTokenExchange: a resource
// server delegating upstream exchanges only a token addressed to one of its own locations.
public partial class TokenExchangeGrantHandlerTests
{
    private const string OwnLocation = "https://mcp.example.com/";
    private const string OtherLocation = "https://other.example.com/";

    /// <summary>
    /// Under AddressedToClient a subject token issued to another client, or to none that can be determined, is
    /// exchanged only when its audience names one of the presenting client's locations, exactly as written there;
    /// Refused exchanges none of them and Any every one.
    /// </summary>
    [Theory]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, "client-A", new[] { OwnLocation }, true)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, "client-A", new[] { OtherLocation, OwnLocation }, true)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, null, new[] { OwnLocation }, true)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, "client-A", new[] { OtherLocation }, false)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, "client-A", new[] { "https://mcp.example.com" }, false)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, "client-A", null, false)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, null, null, false)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, ClientId, null, true)]
    [InlineData(CrossClientSubjectTokenExchange.Refused, "client-A", new[] { OwnLocation }, false)]
    [InlineData(CrossClientSubjectTokenExchange.Refused, ClientId, null, true)]
    [InlineData(CrossClientSubjectTokenExchange.Any, "client-A", null, true)]
    [InlineData(CrossClientSubjectTokenExchange.Any, null, null, true)]
    public async Task ASubjectTokenOfAnotherClient_IsExchangedAsTheClientsSettingSays(
        CrossClientSubjectTokenExchange setting,
        string? owner,
        string[]? audiences,
        bool exchanged)
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = owner,
            Audiences = audiences,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            ResourceServerClient(setting),
            TestContext.Current.CancellationToken);

        Assert.Equal(exchanged, result.TryGetSuccess(out _));
        if (!exchanged)
            Assert.Equal(ErrorCodes.InvalidRequest, result.GetFailure().Error);
    }

    /// <summary>
    /// The issuer is the audience of every access token whose request named no resource, so a client naming it among its
    /// locations exchanges no such token of another client.
    /// </summary>
    [Fact]
    public async Task UnderAddressedToClient_ATokenAddressedToTheIssuer_IsNotExchanged()
    {
        var issuer = SingleIssuer.Tenant.Issuer.OriginalString;
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = "client-A",
            Audiences = [issuer],
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var client = ResourceServerClient(CrossClientSubjectTokenExchange.AddressedToClient);
        client.ResourceLocations = [new Uri(issuer)];

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            client,
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A client naming no location of its own exchanges no token of another client under AddressedToClient, whatever
    /// the token's audience says.
    /// </summary>
    [Fact]
    public async Task UnderAddressedToClient_AClientNamingNoLocation_ExchangesNoTokenOfAnotherClient()
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = "client-A",
            Audiences = [OwnLocation],
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var client = ResourceServerClient(CrossClientSubjectTokenExchange.AddressedToClient);
        client.ResourceLocations = null;

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            client,
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// An actor token is held to the presenting client under AddressedToClient, even one addressed to the client's own
    /// location, and is exchanged from another client only under Any.
    /// </summary>
    [Theory]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, "client-A", false)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, ClientId, true)]
    [InlineData(CrossClientSubjectTokenExchange.Refused, "client-A", false)]
    [InlineData(CrossClientSubjectTokenExchange.Any, "client-A", true)]
    public async Task AnActorTokenOfAnotherClient_IsExchangedOnlyUnderAny(
        CrossClientSubjectTokenExchange setting,
        string actorOwner,
        bool exchanged)
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        const string actorWire = "actor.jwt";
        var actor = new SubjectTokenContext("svc-worker", null, null, null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = actorOwner,
            Audiences = [OwnLocation],
        };
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), actorWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),
        };

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant, request, ResourceServerClient(setting), TestContext.Current.CancellationToken);

        Assert.Equal(exchanged, result.TryGetSuccess(out _));
        if (!exchanged)
            Assert.Equal(ErrorCodes.InvalidRequest, result.GetFailure().Error);
    }

    /// <summary>
    /// A client exchanges no token of another client unless its host says otherwise.
    /// </summary>
    [Fact]
    public void AClient_RefusesTokensOfOtherClients_ByDefault()
        => Assert.Equal(CrossClientSubjectTokenExchange.Refused, new ClientInfo(ClientId).CrossClientSubjectTokenExchange);

    private static ClientInfo ResourceServerClient(CrossClientSubjectTokenExchange setting) => new(ClientId)
    {
        TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
        CrossClientSubjectTokenExchange = setting,
        ResourceLocations = [new Uri(OwnLocation)],
    };
}
