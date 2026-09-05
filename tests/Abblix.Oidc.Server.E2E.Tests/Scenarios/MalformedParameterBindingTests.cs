// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// What the endpoints do with input that cannot be bound at all: a parameter sent twice, and an authorization
/// header that is not a header value.
/// </summary>
/// <remarks>
/// The property under test is that the server answers rather than fails: an endpoint that throws where the
/// pipeline turns it into a 500 hands an unauthenticated caller a way to make it fail on demand, and tells a
/// legitimate client nothing it can act on.
///
/// Sending a parameter twice is not a corner case invented here: OpenID Connect Core 1.0 section 3.1.2.1 says
/// request parameters "MUST NOT be included more than once", so a conforming server has to have an answer for
/// it.
///
/// What these do NOT do is exercise the model binders' own refusal paths, which was the intent they were
/// written with. Coverage says otherwise and coverage is right: a repeated parameter reaches the binder as one
/// comma-joined value rather than as an absent one, so the refusal happens further down. Those paths are
/// driven directly in the MVC unit suite's ModelBinderRefusalTests. These remain because what they assert -
/// that neither input reaches the caller as a server error - is worth asserting on its own, and no unit test
/// of a binder can say it.
/// </remarks>
public class MalformedParameterBindingTests(TestFactory factory) : TestBase(factory)
{
#if !MINIMAL_API_TRANSPORT
    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, string url)
        => await client.GetAsync(url, TestContext.Current.CancellationToken);
#endif

    // Asserts the HTTP shape the MVC pipeline produces. The Minimal API transport reaches the same
    // outcome by a route the in-memory server does not translate: a binding throw propagates to the
    // caller instead of becoming a status, and the request-size limit is endpoint metadata that only
    // Kestrel enforces. Both are asserted for that transport in its own suite, against the mechanism
    // it actually uses. Compiled out here rather than deleted, so the exclusion names its reason.
#if !MINIMAL_API_TRANSPORT
    /// <summary>
    /// A locale list sent twice. Whatever the server decides, it must decide - not fail.
    /// </summary>
    [Fact]
    public async Task A_parameter_repeated_in_the_query_does_not_reach_the_endpoint_as_a_server_error()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();

        var url =
            $"{discovery.AuthorizationEndpoint}" +
            $"?{AuthorizationRequest.Parameters.ClientId}={TestConstants.ConfidentialClientId}" +
            $"&{AuthorizationRequest.Parameters.ResponseType}={ResponseTypes.Code}" +
            $"&{AuthorizationRequest.Parameters.RedirectUri}={Uri.EscapeDataString(TestConstants.RedirectUri)}" +
            $"&{AuthorizationRequest.Parameters.Scope}={Scopes.OpenId}" +
            $"&{AuthorizationRequest.Parameters.State}={Guid.NewGuid():N}" +
            $"&{AuthorizationRequest.Parameters.CodeChallenge}={challenge}" +
            $"&{AuthorizationRequest.Parameters.CodeChallengeMethod}={CodeChallengeMethods.S256}" +
            $"&{AuthorizationRequest.Parameters.UiLocales}=en-US" +
            $"&{AuthorizationRequest.Parameters.UiLocales}=fr-FR";

        var response = await GetAsync(client, url);

        Assert.True(
            (int)response.StatusCode < 500,
            $"a repeated parameter produced {(int)response.StatusCode}, so an unauthenticated caller can make " +
            "the authorization endpoint fail: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
#endif

    // Asserts the HTTP shape the MVC pipeline produces. The Minimal API transport reaches the same
    // outcome by a route the in-memory server does not translate: a binding throw propagates to the
    // caller instead of becoming a status, and the request-size limit is endpoint metadata that only
    // Kestrel enforces. Both are asserted for that transport in its own suite, against the mechanism
    // it actually uses. Compiled out here rather than deleted, so the exclusion names its reason.
#if !MINIMAL_API_TRANSPORT
    /// <summary>
    /// The claims parameter carries JSON, so it goes through a different binder than the locale list - one that
    /// deserializes. It gets the same treatment when repeated.
    /// </summary>
    [Fact]
    public async Task A_json_valued_parameter_repeated_in_the_query_does_not_reach_the_endpoint_as_a_server_error()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();

        var claims = Uri.EscapeDataString("""{"id_token":{"email":null}}""");
        var url =
            $"{discovery.AuthorizationEndpoint}" +
            $"?{AuthorizationRequest.Parameters.ClientId}={TestConstants.ConfidentialClientId}" +
            $"&{AuthorizationRequest.Parameters.ResponseType}={ResponseTypes.Code}" +
            $"&{AuthorizationRequest.Parameters.RedirectUri}={Uri.EscapeDataString(TestConstants.RedirectUri)}" +
            $"&{AuthorizationRequest.Parameters.Scope}={Scopes.OpenId}" +
            $"&{AuthorizationRequest.Parameters.State}={Guid.NewGuid():N}" +
            $"&{AuthorizationRequest.Parameters.CodeChallenge}={challenge}" +
            $"&{AuthorizationRequest.Parameters.CodeChallengeMethod}={CodeChallengeMethods.S256}" +
            $"&{AuthorizationRequest.Parameters.Claims}={claims}" +
            $"&{AuthorizationRequest.Parameters.Claims}={claims}";

        var response = await GetAsync(client, url);

        Assert.True(
            (int)response.StatusCode < 500,
            $"a repeated JSON parameter produced {(int)response.StatusCode}: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
#endif

    /// <summary>
    /// An Authorization header naming a scheme this server does not speak. Measured rather than assumed: the
    /// header grammar accepts this value, reading "this" as the scheme and the rest as its parameter, so the
    /// refusal is the endpoint's and not the binder's - which is the point, since what the caller must get back
    /// is a challenge telling it how to authenticate, not a failure of the request pipeline.
    /// </summary>
    [Fact]
    public async Task An_authorization_header_naming_an_unknown_scheme_is_refused_with_a_challenge()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.UserInfoEndpoint);

        var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.TryAddWithoutValidation("Authorization", "this is not a header value");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.NotEmpty(response.Headers.WwwAuthenticate);
    }

    /// <summary>
    /// A bearer token that is syntactically a header value but not a token this server issued. Sits beside the
    /// case above to keep them apart: one fails to bind, the other binds and fails to validate, and both owe
    /// the caller the same shape of answer.
    /// </summary>
    [Fact]
    public async Task A_bearer_token_that_is_not_ours_is_refused_with_a_challenge()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.UserInfoEndpoint);

        var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, "not-a-token-we-issued");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.NotEmpty(response.Headers.WwwAuthenticate);
    }
}
