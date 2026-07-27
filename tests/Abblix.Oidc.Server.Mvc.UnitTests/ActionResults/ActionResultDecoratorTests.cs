// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.Mvc.UnitTests.ActionResults;

/// <summary>
/// The decorator that carries every header and cookie this adapter attaches, driven through its synchronous
/// entry point.
/// </summary>
/// <remarks>
/// MVC calls <see cref="ActionResult.ExecuteResultAsync"/>, so nothing in the endpoints reaches
/// <see cref="ActionResult.ExecuteResult"/> - but the override is public surface: a host that composes one of
/// these results into its own controller and executes it synchronously gets this path, and the two are separate
/// implementations that can drift apart. An untested one would drift silently, and the way it would fail is the
/// worst kind: the response still goes out, only without the header that carries the protocol meaning.
/// </remarks>
public class ActionResultDecoratorTests
{
    private const string BearerChallenge = $"{TokenTypes.Bearer} realm=\"https://auth.example.com\"";

    [Fact]
    public void The_synchronous_path_applies_the_header_and_executes_the_inner_result()
    {
        var result = new StatusCodeResult(StatusCodes.Status403Forbidden)
            .WithHeader(HeaderNames.WWWAuthenticate, BearerChallenge);

        var response = ActionResultRunner.Run(result);

        Assert.Equal(StatusCodes.Status403Forbidden, response.StatusCode);
        Assert.Equal(BearerChallenge, response.Headers[HeaderNames.WWWAuthenticate].ToString());
    }

    /// <summary>
    /// Decorators nest, so the synchronous path has to recurse through them: the anti-framing helper is two
    /// decorators deep, and a path that applied only the outermost would ship a page with half its protection.
    /// </summary>
    [Fact]
    public void The_synchronous_path_applies_every_layer_of_nested_decorators()
    {
        var result = new StatusCodeResult(StatusCodes.Status200OK).WithAntiFramingHeaders();

        var response = ActionResultRunner.Run(result);

        Assert.Equal(StatusCodes.Status200OK, response.StatusCode);
        Assert.Equal(
            AntiFramingHeaders.ContentSecurityPolicy,
            response.Headers[HeaderNames.ContentSecurityPolicy].ToString());
        Assert.Equal(
            AntiFramingHeaders.XFrameOptions,
            response.Headers[HeaderNames.XFrameOptions].ToString());
    }

    /// <summary>
    /// The multi-line variant appends rather than overwrites, which is what RFC 9449 section 7.1 dual-scheme
    /// emission depends on - collapsing the two challenges into one line loses a scheme.
    /// </summary>
    [Fact]
    public void The_synchronous_path_appends_each_challenge_as_its_own_header_line()
    {
        var result = new StatusCodeResult(StatusCodes.Status401Unauthorized)
            .WithAppendHeader(
                HeaderNames.WWWAuthenticate,
                [$"{TokenTypes.DPoP} algs=\"{SigningAlgorithms.RS256}\"", TokenTypes.Bearer]);

        var response = ActionResultRunner.Run(result);

        var challenges = response.Headers[HeaderNames.WWWAuthenticate];

        Assert.Equal(2, challenges.Count);
        Assert.StartsWith(TokenTypes.DPoP, challenges[0]);
        Assert.Equal(TokenTypes.Bearer, challenges[1]);
    }

    /// <summary>
    /// Cookies travel through the same decorator, and the session-management cookie is set on a response the
    /// authorization endpoint returns, so losing it on this path would silently break session monitoring.
    /// </summary>
    [Fact]
    public void The_synchronous_path_applies_cookies()
    {
        var result = new StatusCodeResult(StatusCodes.Status200OK).WithAppendCookie(
            AuthorizationResponse.Parameters.SessionState,
            "abc.123",
            new CookieOptions { HttpOnly = false });

        var response = ActionResultRunner.Run(result);

        Assert.Contains(
            $"{AuthorizationResponse.Parameters.SessionState}=abc.123",
            response.Headers[HeaderNames.SetCookie].ToString());
    }
}
