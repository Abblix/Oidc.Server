// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Pins how a request asking to choose an account is answered: the session the end user picked on the page goes on
/// alone, a login asked beside it is answered by an authentication on that page, sessions all picked since are asked
/// for again under a new stamp, and a session the request's filters left out sends the end user to log in.
/// </summary>
public class AuthSessionSelectorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset PageShownAt = Now.AddMinutes(-1);

    private readonly FakeTimeProvider _clock = new(Now);

    private Task<Abblix.Utils.Result<AuthSession, Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse>> SelectAsync(
        string[] prompt,
        IDictionary<string, DateTimeOffset>? prompted,
        TimeSpan? maxAge,
        params AuthSession[] sessions)
    {
        var service = new Mock<IAuthSessionService>();
        service.Setup(s => s.GetAvailableAuthSessions()).Returns(() => sessions.ToAsyncEnumerable());
        var cutoff = new Mock<IRevocationCutoffChecker>();
        cutoff.Setup(c => c.IsSessionRefusedAsync(It.IsAny<AuthSession>())).ReturnsAsync(false);

        var request = new ValidAuthorizationRequest(new AuthorizationValidationContext(new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId],
            Prompt = prompt,
            Prompted = prompted is null ? null : new Dictionary<string, DateTimeOffset>(prompted),
            MaxAge = maxAge,
        })
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        });

        return new AuthSessionSelector(service.Object, cutoff.Object, new SubjectTypeConverter(), _clock)
            .SelectAsync(request);
    }

    private static AuthSession Session(string id, DateTimeOffset authenticatedAt, DateTimeOffset? signedInAt)
        => new("subject-" + id, id, authenticatedAt, "local") { SignedInAt = signedInAt };

    [Fact]
    public async Task TheSessionPickedOnThePage_GoesOnAlone()
    {
        var picked = Session("picked", Now.AddHours(-1), PageShownAt.AddSeconds(10));
        var other = Session("other", Now.AddHours(-1), Now.AddHours(-1));

        var result = await SelectAsync(
            [Prompts.SelectAccount], new Dictionary<string, DateTimeOffset> { [Prompts.SelectAccount] = PageShownAt },
            null, picked, other);

        Assert.True(result.TryGetSuccess(out var session));
        Assert.Equal(picked.SessionId, session.SessionId);
    }

    [Fact]
    public async Task SessionsAllPickedSinceThePage_AreAskedForAgainUnderANewStamp()
    {
        var first = Session("first", Now.AddHours(-1), PageShownAt.AddSeconds(10));
        var second = Session("second", Now.AddHours(-1), PageShownAt.AddSeconds(20));

        var result = await SelectAsync(
            [Prompts.SelectAccount], new Dictionary<string, DateTimeOffset> { [Prompts.SelectAccount] = PageShownAt },
            null, first, second);

        Assert.True(result.TryGetFailure(out var response));
        var selection = Assert.IsType<AccountSelectionRequired>(response);
        Assert.Equal(Now, selection.Model.Prompted![Prompts.SelectAccount]);
        Assert.Equal(2, selection.Users.Length);
    }

    /// <summary>
    /// Picking a session authenticated before the page answers the selection but not a login asked beside it.
    /// </summary>
    [Fact]
    public async Task PickingASessionAuthenticatedEarlier_LeavesTheLoginToCome()
    {
        var picked = Session("picked", Now.AddHours(-1), PageShownAt.AddSeconds(10));

        var result = await SelectAsync(
            [Prompts.Login, Prompts.SelectAccount],
            new Dictionary<string, DateTimeOffset>
            {
                [Prompts.SelectAccount] = PageShownAt,
                [Prompts.Login] = PageShownAt,
            },
            null, picked);

        Assert.True(result.TryGetFailure(out var response));
        Assert.IsType<LoginRequired>(response);
    }

    /// <summary>
    /// With no session at all, the selection page that sends the end user to sign in stamps the login asked beside
    /// it too, so the authentication done there answers both.
    /// </summary>
    [Fact]
    public async Task WithoutAnySession_TheSelectionPageStampsTheLoginAskedBesideIt()
    {
        var result = await SelectAsync([Prompts.SelectAccount, Prompts.Login], null, null);

        Assert.True(result.TryGetFailure(out var response));
        var selection = Assert.IsType<AccountSelectionRequired>(response);
        Assert.Equal(Now, selection.Model.Prompted![Prompts.SelectAccount]);
        Assert.Equal(Now, selection.Model.Prompted![Prompts.Login]);
        Assert.Empty(selection.Users);
    }

    /// <summary>
    /// A login page shown before the selection page keeps its own stamp, so the authentication done on it still
    /// answers the login once the end user has chosen the account.
    /// </summary>
    [Fact]
    public async Task TheSelectionPage_KeepsAnEarlierLoginStamp()
    {
        var authenticated = Session("fresh", PageShownAt.AddSeconds(10), PageShownAt.AddSeconds(10));

        var result = await SelectAsync(
            [Prompts.SelectAccount, Prompts.Login],
            new Dictionary<string, DateTimeOffset> { [Prompts.Login] = PageShownAt },
            null, authenticated);

        Assert.True(result.TryGetFailure(out var response));
        var selection = Assert.IsType<AccountSelectionRequired>(response);
        Assert.Equal(PageShownAt, selection.Model.Prompted![Prompts.Login]);
    }

    /// <summary>
    /// A session the request's filters leave out could not get past them by being chosen again, so the end user is
    /// sent to log in rather than round the selection page.
    /// </summary>
    [Fact]
    public async Task ASessionTheFiltersLeftOut_SendsToLogin()
    {
        var tooOld = Session("old", Now.AddHours(-2), Now.AddHours(-2));

        var result = await SelectAsync([Prompts.SelectAccount], null, TimeSpan.FromMinutes(5), tooOld);

        Assert.True(result.TryGetFailure(out var response));
        Assert.IsType<LoginRequired>(response);
    }
}
