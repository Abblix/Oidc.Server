// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// Unit tests for the Minimal API <see cref="EndSessionResponseFormatterDecorator"/>, which clears the
/// check-session cookie when a logout ends a session.
/// </summary>
/// <remarks>
/// Driven through <see cref="HttpResultRunner"/> rather than by reading the result object: the cookie is written
/// while the result executes, so a test that inspects the object sees nothing at all.
/// </remarks>
public class EndSessionResponseFormatterDecoratorTests
{
    private const string CookieName = "Abblix.SessionId";

    private readonly EndSessionResponseFormatterDecorator _decorator =
        new(new AlwaysNoContent(), new ServingTheCookie());

    /// <summary>A deployment that serves the check-session cookie, which is what makes the decorator do anything.
    /// </summary>
    private sealed class ServingTheCookie : ISessionManagementService
    {
        public bool Enabled => true;

        public Cookie GetSessionCookie() => new(CookieName, new Abblix.Oidc.Server.Common.CookieOptions());

        // The rest of the seam belongs to the check-session endpoint, which this decorator never reaches.
        public string GetSessionState(AuthorizationRequest request, string sessionId)
            => throw new NotSupportedException();

        public Task<CheckSessionResponse> GetCheckSessionResponseAsync()
            => throw new NotSupportedException();
    }

    /// <summary>An inner formatter with nothing of its own to say, so the cookie is the only thing under test.
    /// </summary>
    private sealed class AlwaysNoContent : IEndSessionResponseFormatter
    {
        public Task<IResult> FormatResponseAsync(
            EndSessionRequest request, Result<IEndSessionResponse, OidcError> response)
            => Task.FromResult(Results.NoContent());
    }

    private async Task<bool> ClearsTheCookieAsync(Result<IEndSessionResponse, OidcError> response)
    {
        var result = await _decorator.FormatResponseAsync(new EndSessionRequest(), response);
        var executed = await HttpResultRunner.RunAsync(result);

        return executed.Headers.TryGetValue(HeaderNames.SetCookie, out var cookies) &&
               cookies.ToString().Contains(CookieName);
    }

    /// <summary>
    /// A logout that ended the session clears the cookie a client's own page watches, which is how that page
    /// learns the session is over.
    /// </summary>
    [Fact]
    public async Task ASessionThatEnded_ClearsTheCookie()
    {
        Assert.True(await ClearsTheCookieAsync(
            new EndSessionSuccess(PostLogoutRedirectUri: null, FrontChannelLogoutRequestUris: [])));
    }

    /// <summary>
    /// An answer that merely asks the end user leaves it alone: clearing it would tell every watching client the
    /// session is over while it is still live, and the end user may yet decline.
    /// </summary>
    [Fact]
    public async Task AQuestionForTheEndUser_LeavesTheCookieAlone()
    {
        Assert.False(await ClearsTheCookieAsync(new ConfirmationRequired("the-value-that-asks")));
    }

    /// <summary>
    /// A refused request ended nothing either.
    /// </summary>
    [Fact]
    public async Task ARefusal_LeavesTheCookieAlone()
    {
        Assert.False(await ClearsTheCookieAsync(
            new OidcError(Abblix.Oidc.Server.Common.Constants.ErrorCodes.InvalidRequest, "no")));
    }
}
