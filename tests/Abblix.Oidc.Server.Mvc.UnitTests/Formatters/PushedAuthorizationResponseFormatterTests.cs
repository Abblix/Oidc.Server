// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using Moq;
using ParApiModel = Abblix.Oidc.Server.Model.PushedAuthorizationResponse;
using CorePushedAuthorizationResponse = Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Regression coverage for the PAR response formatter: per RFC 9126 section 2.3 PAR is a server-to-server
/// endpoint, so responses must always be JSON and errors must never redirect to a browser-facing
/// login page.
/// </summary>
public class PushedAuthorizationResponseFormatterTests
{
    private readonly PushedAuthorizationResponseFormatter _formatter = new(
        Mock.Of<ITenantAccessor>(accessor => accessor.Current == new TenantContext
        {
            Tenant = new TenantDefinition { Id = "main", Issuer = new Uri("https://auth.example.com") },
        }));

    [Fact]
    public async Task FormatResponseAsync_PushedAuthorizationResponse_ReturnsJsonWith201()
    {
        var request = new AuthorizationRequest();
        var response = new CorePushedAuthorizationResponse(
            request,
            new Uri("urn:ietf:params:oauth:request_uri:abc123"),
            TimeSpan.FromSeconds(60));

        var result = await _formatter.FormatResponseAsync(request, response);

        var json = Assert.IsType<JsonResult>(result);
        Assert.Equal(StatusCodes.Status201Created, json.StatusCode);
        var body = Assert.IsType<ParApiModel>(json.Value);
        Assert.Equal("urn:ietf:params:oauth:request_uri:abc123", body.RequestUri?.OriginalString);
        Assert.Equal(TimeSpan.FromSeconds(60), body.ExpiresIn);
    }

    /// <summary>
    /// RFC 9126 section 2.3 answers an error the way the token endpoint does, and RFC 6749 section 5.2 gives a client
    /// that authenticated through the Authorization header a 401 with a challenge for its scheme.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_InvalidClientError_Returns401WithABasicChallenge()
    {
        var request = new AuthorizationRequest();
        var error = new AuthorizationError(
            request,
            ErrorCodes.InvalidClient,
            "Client authentication failed",
            ResponseMode: ResponseModes.Query,
            RedirectUri: null);

        var response = await ActionResultRunner.RunAsync(await _formatter.FormatResponseAsync(request, error));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        Assert.StartsWith(TokenTypes.Basic, response.Headers[HeaderNames.WWWAuthenticate].ToString());
        Assert.Contains(ErrorCodes.InvalidClient, response.Body);
    }

    [Fact]
    public async Task FormatResponseAsync_InvalidRequestError_ReturnsJson400()
    {
        var request = new AuthorizationRequest();
        var error = new AuthorizationError(
            request,
            ErrorCodes.InvalidRequest,
            "Missing required parameter",
            ResponseMode: ResponseModes.Query,
            RedirectUri: null);

        var response = await ActionResultRunner.RunAsync(await _formatter.FormatResponseAsync(request, error));

        Assert.Equal(StatusCodes.Status400BadRequest, response.StatusCode);
        Assert.Contains(ErrorCodes.InvalidRequest, response.Body);
    }

    /// <summary>
    /// Regression guard: PAR error responses must not redirect to a sign-in page. Following
    /// the redirect lands a programmatic OAuth client on that page's HTML and
    /// breaks RFC 9126 conformance - the bug this formatter was rewritten to fix.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_AnyError_NeverReturnsRedirect()
    {
        var request = new AuthorizationRequest();
        var error = new AuthorizationError(
            request,
            ErrorCodes.InvalidClient,
            "test",
            ResponseMode: ResponseModes.Query,
            RedirectUri: new Uri("https://example.com/cb"));

        var response = await ActionResultRunner.RunAsync(await _formatter.FormatResponseAsync(request, error));

        Assert.False(
            response.Headers.ContainsKey(HeaderNames.Location),
            "a pushed authorization error must be answered to the caller, never redirected to a browser");
        Assert.Contains(ErrorResponse.Parameters.Error, response.Body);
    }
}
