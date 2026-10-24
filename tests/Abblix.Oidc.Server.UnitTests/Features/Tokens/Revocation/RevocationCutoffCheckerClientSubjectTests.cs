// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
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
using Abblix.Oidc.Server.Features.MultiTenancy;

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
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, It.IsAny<string>()))
            .ReturnsAsync((TenantDefinition _, string clientId) => new ClientInfo(clientId));
    }

    private IRevocationCutoffChecker Checker(SubjectTypeConverter? converter = null)
    {
        var issuers = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuers.Setup(p => p.GetIssuer()).Returns(TestConstants.DefaultIssuer);

        return new RevocationCutoffChecker(
            NullLogger<RevocationCutoffChecker>.Instance,
            _cutoffs.Object,
            issuers.Object,
            Options.Create(new OidcOptions()),
            _clients.Object,
            new FixedSubjectTypeConverter(converter ?? new SubjectTypeConverter()), tenantAccessor: SingleIssuer.Accessor);
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

    /// <summary>
    /// An ID token names its client only as its audience, and is measured against the cutoff at that client.
    /// </summary>
    [Fact]
    public async Task AnIdTokenOfTheClient_IsMeasuredByItsAudience()
    {
        SetupCutoff(ClientId, IssuedAt.AddMinutes(10));
        var idToken = Token(clientId: null);
        idToken.Audiences = [ClientId];

        var error = await Checker().CheckAsync(idToken);

        Assert.Equal(JwtError.TokenRevoked, error?.Error);
    }

    /// <summary>
    /// A pairwise client's token carries a pseudonym, while the host revokes the subject it knows the end user by:
    /// the pseudonym is opened first, so the cutoff at that client reaches the token.
    /// </summary>
    [Fact]
    public async Task APairwiseClientsToken_IsMeasuredByTheSubjectBehindItsPseudonym()
    {
        var converter = new SubjectTypeConverter(new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });
        var pairwiseClient = new ClientInfo(ClientId)
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifier = "client.example.com",
        };
        _clients.Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(pairwiseClient);
        SetupCutoff(ClientId, IssuedAt.AddMinutes(10));
        var token = Token(ClientId);
        token.Subject = converter.Convert(Subject, pairwiseClient);
        Assert.NotEqual(Subject, token.Subject);

        var error = await Checker(converter).CheckAsync(token);

        Assert.Equal(JwtError.TokenRevoked, error?.Error);
    }

    /// <summary>
    /// A grant the end user approved before the cutoff at its client is refused at redemption, one approved after it
    /// is not, and one carrying no approval moment is measured against its session's authentication. A grant approved
    /// within the token side's clock tolerance after the cutoff is refused too, since its node's clock may run ahead.
    /// </summary>
    [Theory]
    [InlineData(-600, null, true)]
    [InlineData(600, null, false)]
    [InlineData(2, null, true)]
    [InlineData(null, -600, true)]
    [InlineData(null, 600, false)]
    public async Task AGrant_IsRefusedWhenApprovedBeforeTheCutoffAtItsClient(
        int? authorizedSeconds, int? authenticatedSeconds, bool refused)
    {
        SetupCutoff(ClientId, IssuedAt);
        var grant = new AuthorizedGrant(
            new AuthSession(Subject, "session_7", IssuedAt.AddSeconds(authenticatedSeconds ?? -3600), "local"),
            new AuthorizationContext(ClientId, [], null))
        {
            AuthorizedAt = authorizedSeconds is { } seconds ? IssuedAt.AddSeconds(seconds) : null,
        };

        Assert.Equal(refused, await Checker().IsGrantRefusedAtItsClientAsync(grant));
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
