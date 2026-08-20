// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Mime;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Where the authorization endpoint delivers a refusal, which is decided by whether the request named a
/// redirect URI the client actually registered (OAuth 2.0, RFC 6749 sections 4.1.2.1 and 3.1.2).
/// </summary>
/// <remarks>
/// The whole error path of this adapter's authorization formatter was untested - the mapping of the error onto
/// the response, both delivery branches, and the refusal to redirect. Its MVC counterpart is covered, which is
/// the asymmetry worth closing: two implementations of one contract, one of them measured.
///
/// The security-bearing half is the second case. An authorization request arrives unauthenticated and names
/// where to send the browser afterwards, so a server that redirected to whatever it was handed would forward
/// the user - and the error parameters - to an address the client never registered. RFC 6749 section 4.1.2.1
/// is explicit that the server MUST NOT automatically redirect when the redirect URI is invalid; it has to
/// answer the request itself.
/// </remarks>
public sealed class AuthorizationErrorDeliveryTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = TestFactory.BaseAddress,
    });

    private static async Task<HttpResponseMessage> AuthorizeAsync(
        HttpClient client, JsonObject discovery, IEnumerable<KeyValuePair<string, string>> query)
    {
        var endpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint);
        return await client.GetAsync(OidcFlows.BuildQuery(endpoint, query), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A refusal the client can receive travels back to its own registered address, carrying the error and the
    /// state it sent - the state is how a client tells this refusal from one it never started.
    /// </summary>
    [Fact]
    public async Task An_error_goes_back_to_the_registered_redirect_uri_with_the_state()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var state = Guid.NewGuid().ToString("N");

        var response = await AuthorizeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.ResponseType] = "no_such_response_type",
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = state,
        });

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(TestConstants.RedirectUri, location.GetLeftPart(UriPartial.Path));

        var query = HttpUtility.ParseQueryString(location.Query);
        Assert.False(string.IsNullOrEmpty(query[ResponseParameters.Error]));
        Assert.Equal(state, query[ResponseParameters.State]);
    }

    /// <summary>
    /// RFC 6749 section 4.1.2.1: when the redirect URI is invalid the server MUST NOT redirect to it. This is
    /// the arm that stops the authorization endpoint from being an open redirect on the issuer's own domain,
    /// and it fails in the direction nobody notices - a redirect that "works" looks like success.
    /// </summary>
    [Fact]
    public async Task An_unregistered_redirect_uri_is_answered_directly_and_never_redirected_to()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        var response = await AuthorizeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.RedirectUri] = "https://attacker.example.com/harvest",
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal(MediaTypeNames.Application.Json, response.Content.Headers.ContentType?.MediaType);

        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

        Assert.False(string.IsNullOrEmpty(body[ResponseParameters.Error]?.GetValue<string>()));
    }

    /// <summary>
    /// With <c>response_mode=fragment</c> the parameters go after the <c>#</c> instead of into the query, which
    /// is what keeps them out of the Referer header and out of server logs along the way (OAuth 2.0 Multiple
    /// Response Type Encoding Practices section 2.1). Putting them in the query instead would be a leak no
    /// status code reveals.
    /// </summary>
    [Fact]
    public async Task Fragment_response_mode_puts_the_error_after_the_hash_and_not_in_the_query()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var state = Guid.NewGuid().ToString("N");

        var response = await AuthorizeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.ResponseType] = "no_such_response_type",
            [AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.Fragment,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = state,
        });

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(TestConstants.RedirectUri, location.GetLeftPart(UriPartial.Path));
        Assert.Empty(location.Query);

        var fragment = HttpUtility.ParseQueryString(location.Fragment.TrimStart('#'));
        Assert.False(string.IsNullOrEmpty(fragment[ResponseParameters.Error]));
        Assert.Equal(state, fragment[ResponseParameters.State]);
    }
}
