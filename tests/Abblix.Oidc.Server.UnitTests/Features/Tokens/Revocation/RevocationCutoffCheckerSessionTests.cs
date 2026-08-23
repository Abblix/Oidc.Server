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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// The session half of the cutoff: whether the authorization endpoint may reuse a browser session that a
/// revocation has caught up with.
/// </summary>
/// <remarks>
/// Without this half the token side is a control that can be walked around. A cutoff refuses tokens already
/// issued, and every new authorization stamps a fresh issue time, so a session the revocation never touched
/// mints a replacement that clears the cutoff on the first attempt.
/// <para>
/// The comparison is against the session's authentication time rather than against a flag, and the two tests
/// that pin the direction are the ones about a cutoff older than the session: a boolean would refuse those
/// too, which is what a user signing in after a lifted suspension would hit, over and over.
/// </para>
/// </remarks>
public class RevocationCutoffCheckerSessionTests
{
    private const string Subject = "user_42";
    private const string SessionId = "session_7";

    private static readonly DateTimeOffset AuthenticatedAt = new(2024, 1, 15, 11, 0, 0, TimeSpan.Zero);

    private readonly Mock<IRevocationCutoffRegistry> _cutoffs = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clients = new(MockBehavior.Strict);

    public RevocationCutoffCheckerSessionTests()
    {
        _cutoffs
            .Setup(c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DateTimeOffset?)null);
    }

    private IRevocationCutoffChecker Checker(TimeSpan skew = default)
    {
        var issuers = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuers.Setup(p => p.GetIssuer()).Returns(TestConstants.DefaultIssuer.OriginalString);

        return new RevocationCutoffChecker(
            NullLogger<RevocationCutoffChecker>.Instance,
            _cutoffs.Object,
            issuers.Object,
            Options.Create(new OidcOptions { RevocationCutoffSkew = skew }),
            _clients.Object,
            new SubjectTypeConverter());
    }

    private void SetupCutoff(RevocationScope scope, string principal, DateTimeOffset cutoff)
        => _cutoffs
            .Setup(c => c.GetCutoffAsync(scope, principal, It.IsAny<CancellationToken>()))
            .ReturnsAsync(cutoff);

    private static AuthSession Session(DateTimeOffset? authenticatedAt = null)
        => new(Subject, SessionId, authenticatedAt ?? AuthenticatedAt, "local");

    [Fact]
    public async Task WithNoCutoffRecorded_TheSessionIsUsable()
    {
        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.False(refused);
    }

    /// <summary>
    /// The case the whole change exists for: an administrator suspends the account, and the browser session
    /// that survived it must stop being a way to mint fresh tokens.
    /// </summary>
    [Fact]
    public async Task WhenTheSubjectWasRevokedAfterTheSignIn_TheSessionIsRefused()
    {
        SetupCutoff(RevocationScope.Subject, Subject, AuthenticatedAt.AddMinutes(1));

        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.True(refused);
    }

    /// <summary>
    /// And a revocation of that one session reaches it here too, which is what makes the call named for
    /// ending a session actually end it rather than only stopping its tokens.
    /// </summary>
    [Fact]
    public async Task WhenTheSessionItselfWasRevoked_TheSessionIsRefused()
    {
        SetupCutoff(RevocationScope.Session, SessionId, AuthenticatedAt.AddMinutes(1));

        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.True(refused);
    }

    /// <summary>
    /// A cutoff older than the sign-in leaves it alone. This is the property that lets a suspended user work
    /// again once the suspension is lifted, with no record to clean up - and the reason the check is a
    /// comparison rather than a flag.
    /// </summary>
    [Theory]
    [InlineData(RevocationScope.Subject)]
    [InlineData(RevocationScope.Session)]
    public async Task WhenTheCutoffPredatesTheSignIn_TheSessionIsUsable(RevocationScope scope)
    {
        SetupCutoff(scope, scope is RevocationScope.Subject ? Subject : SessionId, AuthenticatedAt.AddHours(-1));

        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.False(refused);
    }

    /// <summary>
    /// The tolerance widens what a cutoff catches here for the same reason it does on the token side: the
    /// authentication time and the cutoff come from different machines, and only one direction of that error
    /// is recoverable.
    /// </summary>
    [Fact]
    public async Task WhenTheSignInFallsWithinTheSkewAfterACutoff_TheSessionIsRefused()
    {
        SetupCutoff(RevocationScope.Subject, Subject, AuthenticatedAt.AddSeconds(-30));

        var refused = await Checker(TimeSpan.FromMinutes(1)).IsSessionRefusedAsync(Session());

        Assert.True(refused);
    }

    /// <summary>
    /// Another subject's revocation does not touch this session. Stated because every other test here uses a
    /// single principal, so a key that collided would look exactly like the control working.
    /// </summary>
    [Fact]
    public async Task AnotherSubjectsRevocation_LeavesTheSessionAlone()
    {
        SetupCutoff(RevocationScope.Subject, "somebody-else", AuthenticatedAt.AddMinutes(1));

        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.False(refused);
    }

    /// <summary>
    /// The client store is never consulted. The subject here is the one a host revokes, with no pseudonym to
    /// open, so the token side's lookup and its failure modes have no business on the authorization path.
    /// </summary>
    [Fact]
    public async Task TheClientStoreIsNotConsulted()
    {
        SetupCutoff(RevocationScope.Subject, Subject, AuthenticatedAt.AddMinutes(1));

        await Checker().IsSessionRefusedAsync(Session());

        _clients.Verify(p => p.TryFindClientAsync(It.IsAny<string>()), Times.Never);
    }
}
