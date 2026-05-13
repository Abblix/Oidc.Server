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

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;
using ParApiModel = Abblix.Oidc.Server.Mvc.Model.PushedAuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Regression coverage for the PAR response formatter: per RFC 9126 §2.3 PAR is a server-to-server
/// endpoint, so responses must always be JSON and errors must never redirect to a browser-facing
/// login page.
/// </summary>
public class PushedAuthorizationResponseFormatterTests
{
    private readonly PushedAuthorizationResponseFormatter _formatter = new();

    [Fact]
    public async Task FormatResponseAsync_PushedAuthorizationResponse_ReturnsJsonWith201()
    {
        var request = new AuthorizationRequest();
        var response = new PushedAuthorizationResponse(
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

    [Fact]
    public async Task FormatResponseAsync_InvalidClientError_ReturnsJson401()
    {
        var request = new AuthorizationRequest();
        var error = new AuthorizationError(
            request,
            ErrorCodes.InvalidClient,
            "Client authentication failed",
            ResponseMode: "query",
            RedirectUri: null);

        var result = await _formatter.FormatResponseAsync(request, error);

        var json = Assert.IsType<JsonResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, json.StatusCode);
        var body = Assert.IsType<ErrorResponse>(json.Value);
        Assert.Equal(ErrorCodes.InvalidClient, body.Error);
        Assert.Equal("Client authentication failed", body.ErrorDescription);
    }

    [Fact]
    public async Task FormatResponseAsync_InvalidRequestError_ReturnsJson400()
    {
        var request = new AuthorizationRequest();
        var error = new AuthorizationError(
            request,
            ErrorCodes.InvalidRequest,
            "Missing required parameter",
            ResponseMode: "query",
            RedirectUri: null);

        var result = await _formatter.FormatResponseAsync(request, error);

        var json = Assert.IsType<JsonResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, json.StatusCode);
    }

    /// <summary>
    /// Regression guard: PAR error responses must not redirect to a login page. Following
    /// the redirect lands programmatic OAuth clients on the user-facing auth-app HTML and
    /// breaks RFC 9126 conformance — the bug this formatter was rewritten to fix.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_AnyError_NeverReturnsRedirect()
    {
        var request = new AuthorizationRequest();
        var error = new AuthorizationError(
            request,
            ErrorCodes.InvalidClient,
            "test",
            ResponseMode: "query",
            RedirectUri: new Uri("https://example.com/cb"));

        var result = await _formatter.FormatResponseAsync(request, error);

        Assert.IsNotType<RedirectResult>(result);
        Assert.IsNotType<LocalRedirectResult>(result);
        Assert.IsNotType<RedirectToActionResult>(result);
        Assert.IsType<JsonResult>(result);
    }
}
