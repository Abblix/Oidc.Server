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

    /// <summary>
    /// Built with the tolerance a deployment actually gets, so a change to that default is visible here.
    /// An earlier version defaulted the parameter to zero, which asserted the shipped value nowhere.
    /// </summary>
    private IRevocationCutoffChecker Checker(TimeSpan? skew = null)
    {
        var issuers = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuers.Setup(p => p.GetIssuer()).Returns(TestConstants.DefaultIssuer.OriginalString);

        return new RevocationCutoffChecker(
            NullLogger<RevocationCutoffChecker>.Instance,
            _cutoffs.Object,
            issuers.Object,
            Options.Create(skew is { } configured
                ? new OidcOptions { RevocationCutoffSkew = configured }
                : new OidcOptions()),
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
    /// The tolerance that widens the token comparison does not widen this one, so a sign-in shortly after a
    /// revocation is let through.
    /// </summary>
    /// <remarks>
    /// The two sides pay opposite prices for the same widening. On a token it refuses slightly more than the
    /// revocation named, which costs the client one retry - the safe direction. On a session it refuses the
    /// fresh sign-in the user answers the refusal with, and that retry lands inside the same window, so the
    /// tolerance buys a lockout loop rather than a retry. This was the other way round when written, pinned
    /// by this test asserting the refusal.
    /// <para>
    /// What it costs: a session authenticated just before a revocation, on an instance whose clock runs
    /// ahead, reads as later than the cutoff and survives. That window is seconds wide and closes on the
    /// next revocation; a lockout loop does not close at all.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(1)]
    [InlineData(30)]
    public async Task WhenTheSignInFollowsACutoff_TheSessionIsUsableHoweverRecently(int secondsAfter)
    {
        SetupCutoff(RevocationScope.Subject, Subject, AuthenticatedAt.AddSeconds(-secondsAfter));

        var refused = await Checker(TimeSpan.FromMinutes(1)).IsSessionRefusedAsync(Session());

        Assert.False(refused);
    }

    /// <summary>
    /// The boundary itself: a session authenticated in the same instant as the cutoff survives, and one tick
    /// earlier does not.
    /// </summary>
    /// <remarks>
    /// Written as one theory over a single tick because the two cases are the same state either side of the
    /// comparison. Nothing else in this suite visits the boundary, so turning the comparison into its
    /// non-strict form would otherwise leave every test green.
    /// </remarks>
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public async Task AtTheBoundary_OneTickDecidesIt(int ticksTheCutoffFollowsBy, bool expected)
    {
        // A cutoff means everything before this moment is revoked, so a sign-in at the moment itself is not
        // caught: it is not before it. The strict comparison is what says that, and it matches the token
        // side, where the same instant on both is the token surviving too.
        var cutoff = AuthenticatedAt.AddTicks(ticksTheCutoffFollowsBy);
        SetupCutoff(RevocationScope.Subject, Subject, cutoff);

        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.Equal(expected, refused);
    }

    /// <summary>
    /// The session scope takes no tolerance either, the same as the subject scope.
    /// </summary>
    /// <remarks>
    /// Stated separately because the two arms are separate code: an implementation applying the tolerance to
    /// one and not the other passes every other test here.
    /// </remarks>
    [Fact]
    public async Task WhenTheSignInFollowsASessionCutoff_TheSessionIsUsable()
    {
        SetupCutoff(RevocationScope.Session, SessionId, AuthenticatedAt.AddSeconds(-1));

        var refused = await Checker(TimeSpan.FromMinutes(1)).IsSessionRefusedAsync(Session());

        Assert.False(refused);
    }

    /// <summary>
    /// A cutoff on both scopes refuses, and the session scope is what answers.
    /// </summary>
    /// <remarks>
    /// Which arm answers is observable, because the scope is the only handle the log line carries, and the
    /// boolean is the same either way - so asserting the refusal alone would leave the order free to drift
    /// back. Session first matches the order the token side asks in, and it is the narrower answer: it names
    /// the sign-in that was revoked rather than the person across all of theirs.
    /// </remarks>
    [Fact]
    public async Task WhenBothScopesCarryACutoff_TheSessionScopeAnswers()
    {
        SetupCutoff(RevocationScope.Subject, Subject, AuthenticatedAt.AddMinutes(1));
        SetupCutoff(RevocationScope.Session, SessionId, AuthenticatedAt.AddMinutes(1));

        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.True(refused);

        // The subject scope is never reached, which is what says the session arm answered first.
        _cutoffs.Verify(
            c => c.GetCutoffAsync(RevocationScope.Subject, Subject, It.IsAny<CancellationToken>()),
            Times.Never);
    }

    /// <summary>
    /// A session carrying no subject or no identifier is not silently let through on that account.
    /// </summary>
    /// <remarks>
    /// The record declares both non-nullable, but its protobuf form has plain scalars that deserialize an
    /// absent field to an empty string, and a host-supplied session service can produce one directly.
    /// </remarks>
    [Theory]
    [InlineData("", SessionId)]
    [InlineData(Subject, "")]
    public async Task WhenTheSessionNamesNoPrincipal_TheOtherScopeStillDecides(string subject, string sessionId)
    {
        SetupCutoff(RevocationScope.Subject, Subject, AuthenticatedAt.AddMinutes(1));
        SetupCutoff(RevocationScope.Session, SessionId, AuthenticatedAt.AddMinutes(1));

        var session = new AuthSession(subject, sessionId, AuthenticatedAt, "local");

        Assert.True(await Checker().IsSessionRefusedAsync(session));
    }

    /// <summary>
    /// And a cutoff recorded only against the principal the session does not name lets it through.
    /// </summary>
    /// <remarks>
    /// The fail-open shape, stated rather than left to be discovered: an empty principal matches no cutoff,
    /// so the arm that would have refused does not fire, and with the other scope carrying nothing the
    /// session survives. It is a decision on the record because the alternative reads worse - refusing every
    /// session a host produces without one of the two identifiers, which is a configuration fault rather
    /// than a revocation, and refusing it here would report it as a revocation.
    /// </remarks>
    [Theory]
    [InlineData(RevocationScope.Subject, "", SessionId)]
    [InlineData(RevocationScope.Session, Subject, "")]
    public async Task WhenTheSessionNamesNoPrincipalAndOnlyThatScopeCarriesACutoff_ItIsUsable(
        RevocationScope scope, string subject, string sessionId)
    {
        // The cutoff is recorded against the principal this session does not name, so the arm that would
        // have refused has nothing to look up and the other arm has no cutoff to find.
        SetupCutoff(scope, scope is RevocationScope.Subject ? Subject : SessionId, AuthenticatedAt.AddMinutes(1));

        var session = new AuthSession(subject, sessionId, AuthenticatedAt, "local");

        Assert.False(await Checker().IsSessionRefusedAsync(session));
    }

    /// <summary>
    /// Another subject's revocation does not touch this session. Stated because every other test here uses a
    /// single principal, so a key that collided would look exactly like the control working.
    /// </summary>
    [Fact]
    public async Task AnotherSubjectsRevocation_LeavesTheSessionAlone()
    {
        const string somebodyElse = "somebody-else";
        SetupCutoff(RevocationScope.Subject, somebodyElse, AuthenticatedAt.AddMinutes(1));

        var refused = await Checker().IsSessionRefusedAsync(Session());

        Assert.False(refused);

        // Without this the test is the no-cutoff case wearing a different name: the mock matches setups by
        // exact argument, so a cutoff planted under another principal is never consulted and the planting
        // proves nothing. Assert that this session's own principal is what was asked about.
        _cutoffs.Verify(
            c => c.GetCutoffAsync(RevocationScope.Subject, Subject, It.IsAny<CancellationToken>()),
            Times.Once);
        _cutoffs.Verify(
            c => c.GetCutoffAsync(RevocationScope.Subject, somebodyElse, It.IsAny<CancellationToken>()),
            Times.Never);
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
