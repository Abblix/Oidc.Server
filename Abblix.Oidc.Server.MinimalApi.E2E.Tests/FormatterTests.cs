// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Coverage for the adapter's parallel <c>IResult</c> formatter set — the half that does not exist in the core and
/// differs from the MVC <c>ActionResult</c> formatters: JARM response packaging, RFC 6749 cache headers, the JWT vs
/// JSON introspection content negotiation, the form_post HTML response, the check-session document and the
/// UserInfo challenge.
/// </summary>
public sealed class FormatterTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
    });

    [Fact]
    public async Task Jarm_authorize_packs_the_response_into_a_signed_jwt()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (verifier, challenge) = OidcFlows.Pkce();
        var state = Guid.NewGuid().ToString("N");

        // JARM: response_mode=query.jwt makes the AS pack the authorization response into one signed `response` JWT
        // delivered as a query parameter, instead of bare query parameters. Exercises AuthorizationResultFormatter's
        // JARM branch.
        var responseJwt = await client.AuthorizeGetCallbackAsync(OidcFlows.Endpoint(discovery, "authorization_endpoint"),
            new Dictionary<string, string>
            {
                ["client_id"] = TestConstants.ConfidentialClientId,
                ["response_type"] = ResponseTypes.Code,
                ["redirect_uri"] = TestConstants.RedirectUri,
                ["scope"] = Scopes.OpenId,
                ["state"] = state,
                ["nonce"] = Guid.NewGuid().ToString("N"),
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = CodeChallengeMethods.S256,
                ["response_mode"] = ResponseModes.QueryJwt,
            }, "response");

        Assert.Equal(3, responseJwt.Split('.').Length);
        var payload = OidcFlows.DecodeJwtPayload(responseJwt);

        // JARM §2.1 mandated claims, plus the authorization response packed inside the JWT (not on the wire).
        Assert.Equal(
            discovery["issuer"]!.GetValue<string>().TrimEnd('/'),
            payload["iss"]!.GetValue<string>().TrimEnd('/'));
        Assert.Equal(TestConstants.ConfidentialClientId, payload["aud"]!.GetValue<string>());
        Assert.NotNull(payload["exp"]);
        Assert.Equal(state, payload["state"]!.GetValue<string>());

        // The code inside the JWT is real and redeemable.
        var code = payload["code"]!.GetValue<string>();
        var token = await OidcFlows.ExchangeCodeAsync(
            client, discovery, code, verifier, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);
        Assert.NotNull(token["access_token"]);
    }

    [Fact]
    public async Task Token_response_carries_no_store_cache_headers()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        var response = await client.PostFormAsync(OidcFlows.Endpoint(discovery, "token_endpoint"),
            new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["client_id"] = TestConstants.ClientCredentialsClientId,
                ["client_secret"] = TestConstants.ConfidentialClientSecret,
            });

        response.EnsureSuccessStatusCode();

        // RFC 6749 §5.1: the token response MUST carry Cache-Control: no-store. The adapter applies it through
        // OidcResults.WithNoCacheHeaders rather than MVC response filters.
        Assert.True(response.Headers.CacheControl?.NoStore,
            $"expected Cache-Control: no-store, got '{response.Headers.CacheControl}'");
    }

    [Fact]
    public async Task Form_post_response_mode_returns_an_auto_submitting_html_form()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (_, challenge) = OidcFlows.Pkce();
        var state = Guid.NewGuid().ToString("N");

        // response_mode=form_post answers with a 200 text/html auto-submitting form that POSTs the authorization
        // response back to redirect_uri — a custom IResult (the ported AutoPostFormatter), not a redirect.
        var response = await client.GetAsync(OidcFlows.BuildQuery(
            OidcFlows.Endpoint(discovery, "authorization_endpoint"), new Dictionary<string, string>
            {
                ["client_id"] = TestConstants.ConfidentialClientId,
                ["response_type"] = ResponseTypes.Code,
                ["redirect_uri"] = TestConstants.RedirectUri,
                ["scope"] = Scopes.OpenId,
                ["state"] = state,
                ["nonce"] = Guid.NewGuid().ToString("N"),
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = CodeChallengeMethods.S256,
                ["response_mode"] = ResponseModes.FormPost,
            }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        var html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("<form", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(TestConstants.RedirectUri, html);
        Assert.Contains(state, html);
    }

    [Fact]
    public async Task Userinfo_with_invalid_token_challenges_bearer_and_dpop()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        using var request = new HttpRequestMessage(
            HttpMethod.Get, OidcFlows.Endpoint(discovery, "userinfo_endpoint"));
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, "not-a-real-token");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        // The UserInfo formatter advertises both an RFC 6750 Bearer and an RFC 9449 DPoP challenge on a 401 —
        // the dual-challenge OidcResults.Format overload that does not exist in the MVC formatter set.
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.Bearer);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.DPoP);
    }

    [Fact]
    public async Task Introspection_negotiates_signed_jwt_or_plain_json_by_accept_header()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        // RFC 9701: a client registered with introspection_signed_response_alg gets its introspection response wrapped
        // in a signed JWT when it Accepts the +jwt media type, and the plain RFC 7662 JSON otherwise. Register such a
        // client, then introspect its own auth-code token.
        var registerResponse = await client.PostAsync(
            OidcFlows.Endpoint(discovery, "registration_endpoint"),
            JsonContent.Create(new JsonObject
            {
                ["redirect_uris"] = new JsonArray { TestConstants.RedirectUri },
                ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
                ["response_types"] = new JsonArray { ResponseTypes.Code },
                ["token_endpoint_auth_method"] = "client_secret_post",
                ["introspection_signed_response_alg"] = SigningAlgorithms.RS256,
            }),
            TestContext.Current.CancellationToken);
        var registered = JsonNode.Parse(
            await registerResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        var clientId = registered["client_id"]!.GetValue<string>();
        var clientSecret = registered["client_secret"]!.GetValue<string>();

        var accessToken = (await client.AuthCodeTokensViaParAsync(discovery, clientId, clientSecret))
            ["access_token"]!.GetValue<string>();
        var introspectionEndpoint = OidcFlows.Endpoint(discovery, "introspection_endpoint");

        // The +jwt media type yields a 3-segment signed JWT carried under that content type.
        var jwt = await IntrospectWithAcceptAsync(
            client, introspectionEndpoint, clientId, clientSecret, accessToken, MediaTypes.TokenIntrospectionJwt);
        Assert.Equal(MediaTypes.TokenIntrospectionJwt, jwt.Content.Headers.ContentType?.MediaType);
        Assert.Equal(3, (await jwt.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Split('.').Length);

        // A plain JSON Accept yields the RFC 7662 document reporting the token active.
        var json = await IntrospectWithAcceptAsync(
            client, introspectionEndpoint, clientId, clientSecret, accessToken, "application/json");
        Assert.NotEqual(MediaTypes.TokenIntrospectionJwt, json.Content.Headers.ContentType?.MediaType);
        var body = JsonNode.Parse(
            await json.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.True(body["active"]!.GetValue<bool>());
    }

    private static async Task<HttpResponseMessage> IntrospectWithAcceptAsync(
        HttpClient client, string endpoint, string clientId, string clientSecret, string token, string accept)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = token,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
            }),
        };
        request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(accept));
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Check_session_serves_html_with_a_fresh_csp_nonce_per_request()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var checkSession = OidcFlows.Endpoint(discovery, "check_session_iframe");

        var (nonce1, body1) = await FetchCheckSessionAsync(client, checkSession);
        var (nonce2, _) = await FetchCheckSessionAsync(client, checkSession);

        // The template is cached server-side, but the per-request CSP nonce is minted fresh on every execution.
        Assert.NotEqual(nonce1, nonce2);
        Assert.Contains(nonce1, body1);
        Assert.DoesNotContain("{{nonce}}", body1);
    }

    private static async Task<(string Nonce, string Body)> FetchCheckSessionAsync(HttpClient client, string url)
    {
        var response = await client.GetAsync(url, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);

        Assert.True(response.Headers.TryGetValues("Content-Security-Policy", out var cspValues),
            "check_session response is missing the Content-Security-Policy header");
        var match = Regex.Match(string.Join(' ', cspValues!), "nonce-([A-Za-z0-9+/=]+)");
        Assert.True(match.Success, "no nonce in the Content-Security-Policy header");
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return (match.Groups[1].Value, body);
    }
}
