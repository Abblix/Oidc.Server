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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// Unit tests for <see cref="ConfirmationValidator"/>, which decides whether the end user has to be asked before a
/// logout request is acted upon (OpenID Connect RP-Initiated Logout 1.0 section 2).
/// </summary>
public class ConfirmationValidatorTests
{
    private const string CurrentSubject = "user-b";
    private const string CurrentSessionId = "session-b";
    private const string IssuedConfirmation = "issued-for-the-current-session";
    private const string IssuedForAnotherSession = "issued-for-somebody-else";
    private const string ClientOfAnotherSession = "client-of-another-session";

    /// <summary>
    /// When the current session's end user authenticated, in the whole seconds a session read back from its cookie
    /// holds it.
    /// </summary>
    private static readonly DateTimeOffset CurrentAuthenticationTime = new(2026, 11, 23, 10, 15, 30, TimeSpan.Zero);

    private readonly Mock<IAuthSessionService> _authSessionService = new(MockBehavior.Strict);
    private readonly Mock<ILogoutConfirmationStore> _confirmationStore = new(MockBehavior.Strict);
    private readonly Mock<ISessionClientRegistry> _sessionClients = new(MockBehavior.Strict);
    private readonly ConfirmationValidator _validator;

    public ConfirmationValidatorTests()
    {
        // These rows exercise public clients (the default subject type), so a converter with no pairwise settings
        // is the production path: it passes a subject through unchanged.
        _validator = new ConfirmationValidator(
            _authSessionService.Object,
            new FixedSubjectTypeConverter(new SubjectTypeConverter()),
            _sessionClients.Object,
            _confirmationStore.Object);

        SignedIn(null);

        // Only the value this session was asked with is an answer; anything else was never issued, belongs to
        // another session, or has been spent.
        _confirmationStore
            .Setup(s => s.RedeemLogoutConfirmationAsync(TestTenant.Matched, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        _confirmationStore
            .Setup(s => s.RedeemLogoutConfirmationAsync(TestTenant.Matched, CurrentSessionId, IssuedConfirmation))
            .ReturnsAsync(true);

        // The request's client signed in to the current session; another session knows only a client of its own
        _sessionClients
            .Setup(s => s.GetClientsAsync(TestTenant.Matched, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([ClientOfAnotherSession]);
        _sessionClients
            .Setup(s => s.GetClientsAsync(TestTenant.Matched, CurrentSessionId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([ClientOfAnotherSession, TestConstants.DefaultClientId]);
    }

    /// <summary>
    /// Answers the current session for every read, or none when <paramref name="session"/> is null.
    /// </summary>
    private void SignedIn(AuthSession? session)
        => _authSessionService.Setup(s => s.AuthenticateAsync()).ReturnsAsync(session);

    /// <summary>
    /// A session whose end user authenticated at <see cref="CurrentAuthenticationTime"/>, unless another time is given.
    /// </summary>
    private static AuthSession Session(string subject, string sessionId, DateTimeOffset? authenticationTime = null)
        => new(subject, sessionId, authenticationTime ?? CurrentAuthenticationTime, "local");

    private static EndSessionValidationContext CreateContext(
        string? confirmation = null,
        string? idTokenHint = null,
        string? hintSubject = null,
        string? hintSessionId = null,
        DateTimeOffset? hintAuthenticationTime = null,
        string clientId = TestConstants.DefaultClientId)
    {
        var request = new EndSessionRequest
        {
            Confirmation = confirmation,
            IdTokenHint = idTokenHint,
        };

        var context = new EndSessionValidationContext(request)
        {
            ClientInfo = new ClientInfo(clientId),
        };

        if (hintSubject != null || hintSessionId != null || hintAuthenticationTime != null)
        {
            context.IdToken = new JsonWebToken
            {
                Payload =
                {
                    Subject = hintSubject,
                    SessionId = hintSessionId,
                    AuthenticationTime = hintAuthenticationTime,
                },
            };
        }

        return context;
    }

    /// <summary>
    /// Runs the validator and answers whether the end user has to be asked. A refusal is a separate outcome and
    /// none of these rows produces one, so it is asserted away here rather than in every row.
    /// </summary>
    private async Task<bool> AsksTheEndUserAsync(EndSessionValidationContext context)
    {
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(error);
        return context.ConfirmationRequired;
    }

    /// <summary>
    /// The end user's own answer, which this server issued for the session in question, ends it without a further
    /// question. The value is spent in the same breath, so the page cannot be submitted twice.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTheIssuedConfirmation_AsksNobodyAndSpendsIt()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.False(await AsksTheEndUserAsync(CreateContext(confirmation: IssuedConfirmation)));

        _confirmationStore.Verify(
            s => s.RedeemLogoutConfirmationAsync(TestTenant.Matched, CurrentSessionId, IssuedConfirmation), Times.Once);
    }

    /// <summary>
    /// A value that was never issued, or that has already been spent, is no answer at all: the store says it names
    /// no session, and the end user is asked.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAConfirmationNobodyIssued_AsksTheEndUser()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.True(await AsksTheEndUserAsync(CreateContext(confirmation: "made-up")));
    }

    /// <summary>
    /// An answer given about one session does not end another, which is what stops a confirmation captured in one
    /// browser from being replayed against the session somebody else signs into.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAConfirmationIssuedForAnotherSession_AsksTheEndUser()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.True(await AsksTheEndUserAsync(CreateContext(confirmation: IssuedForAnotherSession)));
    }

    /// <summary>
    /// A hint naming the session that is signed in stands in for the answer, which is what lets an ordinary logout
    /// go through without a page in between (section 2 puts the question under SHOULD in that case).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintNamingTheCurrentSession_AsksNobody()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.False(await AsksTheEndUserAsync(CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: CurrentSubject,
            hintSessionId: CurrentSessionId)));
    }

    /// <summary>
    /// A client not told the session at logout receives ID tokens without <c>sid</c>. Its hint still belongs to the
    /// current session when it names the end user signed in now, the authentication that began this session, and a
    /// client recorded as signed in to it: RP-Initiated Logout 1.0 section 2 has the OP accept a hint when "the RP
    /// identified by the ID Token's aud claim and/or sid claim has a current session", so the end user is not asked.
    /// The time is compared in the whole seconds an ID token states it in.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintOfTheCurrentAuthenticationByAClientOfTheSessionAndNoSid_AsksNobody()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId, CurrentAuthenticationTime.AddMilliseconds(400)));

        Assert.False(await AsksTheEndUserAsync(CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: CurrentSubject,
            hintAuthenticationTime: CurrentAuthenticationTime)));
    }

    /// <summary>
    /// Each condition a hint without <c>sid</c> is held to, broken alone: another end user, another authentication
    /// of the same one (an earlier session, or one in another browser), a client the current session never signed in
    /// to, and a hint stating no authentication time. Each leaves the hint unproven to belong to this session, and
    /// section 2 then says the OP "MUST ask the End-User".
    /// </summary>
    /// <param name="hintSubject">The end user the hint names.</param>
    /// <param name="secondsBeforeTheSession">How long before the session's authentication the hint's was, or null
    /// for a hint stating none.</param>
    /// <param name="clientId">The client the hint was issued to.</param>
    [Theory]
    [InlineData("user-a", 0, TestConstants.DefaultClientId)]
    [InlineData(CurrentSubject, 1, TestConstants.DefaultClientId)]
    [InlineData(CurrentSubject, 0, "client-signed-in-elsewhere")]
    [InlineData(CurrentSubject, null, TestConstants.DefaultClientId)]
    public async Task ValidateAsync_WithHintWithoutSidNotShownToBelongToTheSession_AsksTheEndUser(
        string hintSubject, int? secondsBeforeTheSession, string clientId)
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var context = CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: hintSubject,
            hintAuthenticationTime: CurrentAuthenticationTime.AddSeconds(-secondsBeforeTheSession ?? 0),
            clientId: clientId);

        if (secondsBeforeTheSession == null)
            context.IdToken!.Payload.AuthenticationTime = null;

        Assert.True(await AsksTheEndUserAsync(context));
    }

    /// <summary>
    /// With no client recorded for the session, as when the records have expired, whether the hint's client signed in
    /// to it cannot be decided, and the end user is asked.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintWithoutSidAndNoClientsRecorded_AsksTheEndUser()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));
        _sessionClients
            .Setup(s => s.GetClientsAsync(TestTenant.Matched, CurrentSessionId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);

        Assert.True(await AsksTheEndUserAsync(CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: CurrentSubject,
            hintAuthenticationTime: CurrentAuthenticationTime)));
    }

    /// <summary>
    /// A hint about somebody else does not speak for the person signed in now: section 2 says the OP "MUST ask the
    /// End-User this question ... if the supplied ID Token does not belong to the current OP session with the RP
    /// and/or currently logged in End-User". Without this, a client holding an old ID token of any end user could
    /// sign out whoever is there now.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintNamingAnotherSubject_AsksTheEndUser()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.True(await AsksTheEndUserAsync(CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: "user-a",
            hintSessionId: CurrentSessionId)));
    }

    /// <summary>
    /// The same person can hold an ID token from a session that has since been replaced, and that token names a
    /// session this request is not about.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintNamingAnotherSession_AsksTheEndUser()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.True(await AsksTheEndUserAsync(CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: CurrentSubject,
            hintSessionId: "session-a",
            hintAuthenticationTime: CurrentAuthenticationTime)));
    }

    /// <summary>
    /// With nobody signed in there is no session to end and nobody to ask, so nothing is asked and no answer is
    /// looked up.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNobodySignedIn_AsksNobody()
    {
        Assert.False(await AsksTheEndUserAsync(CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: "user-a")));

        _confirmationStore.Verify(
            s => s.RedeemLogoutConfirmationAsync(It.IsAny<TenantDefinition>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// A request carrying neither an answer nor a hint is the case the question exists for.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNeitherAnswerNorHint_AsksTheEndUser()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.True(await AsksTheEndUserAsync(CreateContext()));
    }

    /// <summary>
    /// A hint that did not parse leaves nothing to compare, whatever the request carried as its text, so the end
    /// user is asked.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not-a-token")]
    public async Task ValidateAsync_WithAHintThatNamesNothing_AsksTheEndUser(string idTokenHint)
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.True(await AsksTheEndUserAsync(CreateContext(idTokenHint: idTokenHint)));
    }

    /// <summary>
    /// A pairwise client never sees the subject the session holds, so the comparison is made in that client's own
    /// spelling of the end user: its pseudonym matches, and the real subject, which only this server knows, does
    /// not. Comparing the two strings directly would have it the other way round. The pseudonym is the one of the
    /// tenant the request is served at: the converter answers it for that tenant alone.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateAsync_WithPairwiseClient_ComparesTheSubjectThatClientSees(bool hintCarriesThePseudonym)
    {
        var converter = new SubjectTypeConverter(
            new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });

        var client = new ClientInfo(TestConstants.DefaultClientId)
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifier = "client.example.com",
        };

        var pseudonym = converter.Convert(CurrentSubject, client);
        var subjects = new Mock<ISubjectTypeConverter>();
        subjects.Setup(s => s.Convert(TestTenant.Matched, CurrentSubject, client)).Returns(pseudonym);

        var validator = new ConfirmationValidator(
            _authSessionService.Object, subjects.Object, _sessionClients.Object, _confirmationStore.Object);

        SignedIn(Session(CurrentSubject, CurrentSessionId));

        Assert.NotEqual(CurrentSubject, pseudonym);

        var context = CreateContext(
            idTokenHint: "id_token_value",
            hintSubject: hintCarriesThePseudonym ? pseudonym : CurrentSubject,
            hintSessionId: CurrentSessionId);
        context.ClientInfo = client;

        var error = await validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(error);
        Assert.Equal(!hintCarriesThePseudonym, context.ConfirmationRequired);
    }
}
