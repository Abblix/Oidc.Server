// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Features.SessionManagement;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Features.SessionManagement;

/// <summary>
/// Unit tests for <see cref="EndSessionResponseFormatterDecorator"/>, which clears the check-session cookie when a
/// logout ends a session.
/// </summary>
public class EndSessionResponseFormatterDecoratorTests
{
    private readonly Mock<IEndSessionResponseFormatter> _inner = new(MockBehavior.Strict);
    private readonly EndSessionResponseFormatterDecorator _decorator;

    public EndSessionResponseFormatterDecoratorTests()
    {
        var sessionManagement = new Mock<ISessionManagementService>(MockBehavior.Strict);
        sessionManagement.Setup(s => s.Enabled).Returns(true);
        sessionManagement
            .Setup(s => s.GetSessionCookie())
            .Returns(new Cookie("Abblix.SessionId", new Abblix.Oidc.Server.Common.CookieOptions()));

        _inner
            .Setup(f => f.FormatResponseAsync(It.IsAny<EndSessionRequest>(), It.IsAny<Result<IEndSessionResponse, OidcError>>()))
            .ReturnsAsync(new NoContentResult());

        _decorator = new EndSessionResponseFormatterDecorator(_inner.Object, sessionManagement.Object);
    }

    /// <summary>
    /// A logout that ended the session clears the cookie a client's own page watches, which is how that page
    /// learns the session is over.
    /// </summary>
    [Fact]
    public async Task ASessionThatEnded_ClearsTheCookie()
    {
        var result = await _decorator.FormatResponseAsync(
            new EndSessionRequest(),
            new EndSessionSuccess(PostLogoutRedirectUri: null, FrontChannelLogoutRequestUris: []));

        Assert.IsType<ActionResultDecorator>(result);
    }

    /// <summary>
    /// An answer that merely asks the end user leaves it alone: clearing it would tell every watching client the
    /// session is over while it is still live, and the end user may yet decline.
    /// </summary>
    [Fact]
    public async Task AQuestionForTheEndUser_LeavesTheCookieAlone()
    {
        var result = await _decorator.FormatResponseAsync(
            new EndSessionRequest(),
            new ConfirmationRequired("the-value-that-asks"));

        Assert.IsNotType<ActionResultDecorator>(result);
    }

    /// <summary>
    /// A refused request ended nothing either.
    /// </summary>
    [Fact]
    public async Task ARefusal_LeavesTheCookieAlone()
    {
        var result = await _decorator.FormatResponseAsync(
            new EndSessionRequest(),
            new OidcError(Common.Constants.ErrorCodes.InvalidRequest, "no"));

        Assert.IsNotType<ActionResultDecorator>(result);
    }
}
