// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Response-mode downgrade backstop (RFC 9700) end-to-end. A client that opts in to the per-client
/// <c>AllowedResponseModes</c> allow-list, pinned to form_post, exchanges the code from its backend and
/// never needs it in the browser. A crafted authorization request that names an exposing delivery mode
/// (query or fragment), or omits <c>response_mode</c> to inherit the query default, is rejected with
/// <c>invalid_request</c>; form_post is accepted and the code is delivered by an auto-submitting POST.
/// </summary>
public class ResponseModeRestrictionTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// Verifies that the pinned client is rejected when the request names query or fragment, or omits
    /// response_mode (inheriting the query default). Each rejection is delivered on the requested or
    /// effective channel, so the test reads the error from whichever of query/fragment carries it.
    /// </summary>
    [Theory]
    [InlineData(ResponseModes.Query)]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(null)]
    public async Task PinnedClient_ExposingOrOmittedMode_IsRejected(string? responseMode)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();

        var queryParams = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ResponseModePinnedClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };
        if (responseMode is not null)
            queryParams[AuthorizationRequest.Parameters.ResponseMode] = responseMode;

        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, queryParams);
        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found,
            $"/authorize returned {(int)response.StatusCode}, expected an error redirect. Body: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var location = response.Headers.Location
            ?? throw new InvalidOperationException("/authorize did not set Location header");

        // query and the omitted default deliver the error in the query string; fragment delivers it in
        // the fragment. Read whichever part carries the parameters.
        var carrier = location.Query.Length > 0 ? location.Query : location.Fragment;
        var callback = System.Web.HttpUtility.ParseQueryString(carrier.TrimStart('?', '#'));

        Assert.Equal(ErrorCodes.InvalidRequest, callback["error"]);
        Assert.Null(callback["code"]);
    }

    /// <summary>
    /// Verifies that the pinned client is accepted when it requests form_post: the AS renders a 200
    /// auto-submitting HTML form that POSTs the code to the redirect_uri, rather than an error redirect.
    /// </summary>
    [Fact]
    public async Task PinnedClient_FormPost_IsAccepted()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();

        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ResponseModePinnedClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.FormPost,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });
        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        // The auto-submitting form POSTs the authorization response back to the registered redirect_uri.
        Assert.Contains(TestConstants.RedirectUri, body);
        Assert.Contains(TokenRequest.Parameters.Code, body);
    }
}
