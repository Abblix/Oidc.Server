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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using CorePushedAuthorizationResponse =
    Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// What the pushed authorization endpoint answers, which is JSON in every case - RFC 9126 section 2.3 makes it
/// a server-to-server endpoint, so nothing it returns is meant for a browser.
/// </summary>
/// <remarks>
/// The twin of the MVC suite's <c>PushedAuthorizationResponseFormatterTests</c>. Its error branch had no test
/// on this adapter at all, and it is the branch that carries a regression the MVC formatter was rewritten to
/// fix: a PAR error must not redirect. A programmatic client following a redirect from this endpoint lands on
/// the user-facing login page and reads HTML where it expected an error object, which is why the refusal to
/// redirect is asserted here rather than assumed from the status code.
/// </remarks>
public class PushedAuthorizationResponseFormatterTests
{
    private readonly PushedAuthorizationResponseFormatter _formatter = new();

    private static AuthorizationError Error(string errorCode, Uri? redirectUri = null)
        => new(
            new AuthorizationRequest(),
            errorCode,
            "the description the client reads",
            ResponseMode: ResponseModes.Query,
            RedirectUri: redirectUri);

    /// <summary>
    /// RFC 9126 section 2.2: a stored request is answered with 201 and the handle the client presents at the
    /// authorization endpoint, together with how long it is good for.
    /// </summary>
    [Fact]
    public async Task A_stored_request_is_answered_with_its_handle_and_lifetime()
    {
        var request = new AuthorizationRequest();
        var response = new CorePushedAuthorizationResponse(
            request,
            new Uri("urn:ietf:params:oauth:request_uri:abc123"),
            TimeSpan.FromSeconds(60));

        var result = await HttpResultRunner.RunAsync(await _formatter.FormatResponseAsync(request, response));

        Assert.Equal(StatusCodes.Status201Created, result.StatusCode);
        Assert.Contains("urn:ietf:params:oauth:request_uri:abc123", result.Body);
    }

    /// <summary>
    /// RFC 6749 section 5.2: a failure to authenticate the client is a 401, and everything else the endpoint
    /// refuses is a 400. The two are separate arms, so both are driven - answering 400 for a bad secret would
    /// tell the client its request was malformed when its credentials were.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidClient, StatusCodes.Status401Unauthorized)]
    [InlineData(ErrorCodes.InvalidRequest, StatusCodes.Status400BadRequest)]
    [InlineData(ErrorCodes.InvalidRedirectUri, StatusCodes.Status400BadRequest)]
    public async Task An_error_is_answered_with_json_at_the_status_its_kind_calls_for(
        string errorCode, int expectedStatusCode)
    {
        var request = new AuthorizationRequest();

        var result = await HttpResultRunner.RunAsync(
            await _formatter.FormatResponseAsync(request, Error(errorCode)));

        Assert.Equal(expectedStatusCode, result.StatusCode);
        Assert.Contains(errorCode, result.Body);
        Assert.Contains("the description the client reads", result.Body);
    }

    /// <summary>
    /// The regression this endpoint's formatter exists to prevent: even when the request named a redirect URI,
    /// an error is returned to the caller rather than sent to a browser. PAR is called by the client's back end,
    /// which follows redirects by default and would parse a login page as its error response.
    /// </summary>
    [Fact]
    public async Task An_error_is_never_delivered_as_a_redirect_even_with_a_redirect_uri_at_hand()
    {
        var request = new AuthorizationRequest();
        var error = Error(ErrorCodes.InvalidRequest, new Uri("https://client.example.com/cb"));

        var result = await HttpResultRunner.RunAsync(await _formatter.FormatResponseAsync(request, error));

        Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
        Assert.False(
            result.Headers.ContainsKey(Microsoft.Net.Http.Headers.HeaderNames.Location),
            "a pushed authorization error must be answered to the caller, never redirected to a browser");
        Assert.Contains(ResponseParameters.Error, result.Body);
    }
}
