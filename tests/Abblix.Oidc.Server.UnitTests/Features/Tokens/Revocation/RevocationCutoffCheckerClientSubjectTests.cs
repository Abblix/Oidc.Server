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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// The token half of a cutoff recorded against one end user at one client: a token that client holds for them,
/// issued before the cutoff, is refused, while their tokens at other clients and tokens naming no client are not.
/// </summary>
public class RevocationCutoffCheckerClientSubjectTests
{
    private const string Subject = "user_42";
    private const string ClientId = "client_9";

    private static readonly DateTimeOffset IssuedAt = new(2024, 1, 15, 11, 0, 0, TimeSpan.Zero);

    private readonly Mock<IRevocationCutoffRegistry> _cutoffs = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clients = new(MockBehavior.Strict);

    public RevocationCutoffCheckerClientSubjectTests()
    {
        _cutoffs
            .Setup(c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DateTimeOffset?)null);
        _clients
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync((string clientId) => new ClientInfo(clientId));
    }

    private IRevocationCutoffChecker Checker()
    {
        var issuers = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuers.Setup(p => p.GetIssuer()).Returns(TestConstants.DefaultIssuer);

        return new RevocationCutoffChecker(
            NullLogger<RevocationCutoffChecker>.Instance,
            _cutoffs.Object,
            issuers.Object,
            Options.Create(new OidcOptions()),
            _clients.Object,
            new SubjectTypeConverter());
    }

    private static JsonWebTokenPayload Token(string? clientId) => new(new())
    {
        Issuer = TestConstants.DefaultIssuer.OriginalString,
        Subject = Subject,
        ClientId = clientId,
        IssuedAt = IssuedAt,
    };

    private void SetupCutoff(string clientId, DateTimeOffset cutoff)
        => _cutoffs
            .Setup(c => c.GetCutoffAsync(
                RevocationScope.ClientSubject,
                RevocationPrincipal.ClientSubject(clientId, Subject),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(cutoff);

    [Fact]
    public async Task ATokenOfTheClientIssuedBeforeTheCutoff_IsRefused()
    {
        SetupCutoff(ClientId, IssuedAt.AddMinutes(10));

        var error = await Checker().CheckAsync(Token(ClientId));

        Assert.Equal(JwtError.TokenRevoked, error?.Error);
    }

    [Fact]
    public async Task ATokenOfTheClientIssuedAfterTheCutoff_IsAccepted()
    {
        SetupCutoff(ClientId, IssuedAt.AddMinutes(-10));

        Assert.Null(await Checker().CheckAsync(Token(ClientId)));
    }

    [Fact]
    public async Task ATokenOfAnotherClient_IsAccepted()
    {
        SetupCutoff("another_client", IssuedAt.AddMinutes(10));

        Assert.Null(await Checker().CheckAsync(Token(ClientId)));
    }

    [Fact]
    public async Task ATokenNamingNoClient_IsNotMeasuredAgainstAClientCutoff()
    {
        Assert.Null(await Checker().CheckAsync(Token(clientId: null)));

        _cutoffs.Verify(
            c => c.GetCutoffAsync(RevocationScope.ClientSubject, It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
