// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Net.Http.Headers;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Coverage for the adapter's parallel <c>IResult</c> formatter set - the half that does not exist in the core and
/// differs from the MVC <c>ActionResult</c> formatters: JARM response packaging, RFC 6749 cache headers, the JWT vs
/// JSON introspection content negotiation, the form_post HTML response, the check-session document and the
/// UserInfo challenge.
/// </summary>
public sealed class FormatterTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = TestFactory.BaseAddress,
    });

    [Fact]
    public async Task Jarm_authorize_packs_the_response_into_a_signed_jwt()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (verifier, challenge) = OidcFlows.Pkce();
        var state = Guid.NewGuid().ToString("N");

        // JARM: response_mode=query.jwt makes the AS pack the authorization response into one signed `response` JWT
        // delivered as a query parameter, instead of bare query parameters. Exercises AuthorizationResponseFormatter's
        // JARM branch.
        var responseJwt = await client.AuthorizeGetCallbackAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint),
            new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [AuthorizationRequest.Parameters.State] = state,
                [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
                [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
                [AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.QueryJwt,
            }, ResponseParameters.Response);

        Assert.Equal(3, responseJwt.Split('.').Length);
        var payload = OidcFlows.DecodeJwtPayload(responseJwt);

        // JARM §2.1 mandated claims, plus the authorization response packed inside the JWT (not on the wire).
        Assert.Equal(
            discovery[ConfigurationResponse.Parameters.Issuer]!.GetValue<string>().TrimEnd('/'),
            payload[IanaClaimTypes.Iss]!.GetValue<string>().TrimEnd('/'));
        Assert.Equal(TestConstants.ConfidentialClientId, payload[IanaClaimTypes.Aud]!.GetValue<string>());
        Assert.NotNull(payload[IanaClaimTypes.Exp]);
        Assert.Equal(state, payload[ResponseParameters.State]!.GetValue<string>());

        // The code inside the JWT is real and redeemable.
        var code = payload[ResponseParameters.Code]!.GetValue<string>();
        var token = await OidcFlows.ExchangeCodeAsync(
            client, discovery, code, verifier, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);
        Assert.NotNull(token[ResponseParameters.AccessToken]);
    }

    [Fact]
    public async Task Token_response_carries_no_store_cache_headers()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        var response = await client.PostFormAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.TokenEndpoint),
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [ClientRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
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
        // response back to redirect_uri - a custom IResult (the ported AutoPostFormatter), not a redirect.
        var response = await client.GetAsync(OidcFlows.BuildQuery(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint), new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [AuthorizationRequest.Parameters.State] = state,
                [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
                [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
                [AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.FormPost,
            }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(MediaTypeNames.Text.Html, response.Content.Headers.ContentType?.MediaType);
        var html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("<form", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(TestConstants.RedirectUri, html);
        Assert.Contains(state, html);

        // The auto-submit page must never be framed by another origin (clickjacking defense, RFC 9700 §4.16).
        Assert.True(response.Headers.TryGetValues("Content-Security-Policy", out var csp));
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.True(response.Headers.TryGetValues("X-Frame-Options", out var xFrameOptions));
        Assert.Contains("DENY", xFrameOptions);
    }

    [Fact]
    public async Task Userinfo_with_invalid_token_challenges_bearer_and_dpop()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        using var request = new HttpRequestMessage(
            HttpMethod.Get, OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.UserInfoEndpoint));
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, "not-a-real-token");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        // The UserInfo formatter advertises both an RFC 6750 Bearer and an RFC 9449 DPoP challenge on a 401 -
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
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.RegistrationEndpoint),
            JsonContent.Create(new JsonObject
            {
                [ClientRegistrationRequest.Parameters.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
                [ClientRegistrationRequest.Parameters.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
                [ClientRegistrationRequest.Parameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
                [ClientRegistrationRequest.Parameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
                [ClientRegistrationRequest.Parameters.IntrospectionSignedResponseAlg] = SigningAlgorithms.RS256,
            }),
            TestContext.Current.CancellationToken);
        var registered = JsonNode.Parse(
            await registerResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        var clientId = registered[ClientRequest.Parameters.ClientId]!.GetValue<string>();
        var clientSecret = registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>();

        var accessToken = (await client.AuthCodeTokensViaParAsync(discovery, clientId, clientSecret))
            [ResponseParameters.AccessToken]!.GetValue<string>();
        var introspectionEndpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.IntrospectionEndpoint);

        // The +jwt media type yields a 3-segment signed JWT carried under that content type.
        var jwt = await IntrospectWithAcceptAsync(
            client, introspectionEndpoint, clientId, clientSecret, accessToken, MediaTypes.TokenIntrospectionJwt);
        Assert.Equal(MediaTypes.TokenIntrospectionJwt, jwt.Content.Headers.ContentType?.MediaType);
        Assert.Equal(3, (await jwt.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Split('.').Length);

        // A plain JSON Accept yields the RFC 7662 document reporting the token active.
        var json = await IntrospectWithAcceptAsync(
            client, introspectionEndpoint, clientId, clientSecret, accessToken, MediaTypeNames.Application.Json);
        Assert.NotEqual(MediaTypes.TokenIntrospectionJwt, json.Content.Headers.ContentType?.MediaType);
        var body = JsonNode.Parse(
            await json.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.True(body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    private static async Task<HttpResponseMessage> IntrospectWithAcceptAsync(
        HttpClient client, string endpoint, string clientId, string clientSecret, string token, string accept)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = token,
                [ClientRequest.Parameters.ClientId] = clientId,
                [ClientRequest.Parameters.ClientSecret] = clientSecret,
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
        var checkSession = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.CheckSessionIframe);

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
        Assert.Equal(MediaTypeNames.Text.Html, response.Content.Headers.ContentType?.MediaType);

        Assert.True(response.Headers.TryGetValues(HeaderNames.ContentSecurityPolicy, out var cspValues),
            "check_session response is missing the Content-Security-Policy header");
        var match = Regex.Match(
            string.Join(' ', cspValues!), "nonce-([A-Za-z0-9+/=]+)", RegexOptions.None, TimeSpan.FromSeconds(1));
        Assert.True(match.Success, "no nonce in the Content-Security-Policy header");
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return (match.Groups[1].Value, body);
    }
}
