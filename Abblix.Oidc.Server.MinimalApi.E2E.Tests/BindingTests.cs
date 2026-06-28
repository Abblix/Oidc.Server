// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.E2E.TestHost.TestInfrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Coverage for the generated <c>BindAsync</c> over the GET (query-or-form) and JSON-body paths the core
/// form-POST tests do not reach: the <c>SupportsGet</c> models (AuthorizationRequest, UserInfoRequest,
/// EndSessionRequest) bound from a query string with their special-format markers, plus the device-authorization
/// and dynamic-client-registration request shapes.
/// </summary>
public sealed class BindingTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
    });

    [Fact]
    public async Task Authorize_get_binds_every_special_marker_and_issues_a_code()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (verifier, challenge) = OidcFlows.Pkce();

        // A GET /authorize carrying one of every special-format field. If any fails to parse, the server answers
        // with an error (or an error redirect) rather than a code, so a returned code proves the generated
        // AuthorizationRequest.BindAsync read them all from the query: scope (space-separated), max_age (seconds),
        // ui_locales (culture list), claims (JSON-in-a-field) and resource (repeated Uri[]).
        var query = new Dictionary<string, string>
        {
            ["client_id"] = TestConstants.ConfidentialClientId,
            ["response_type"] = ResponseTypes.Code,
            ["redirect_uri"] = TestConstants.RedirectUri,
            ["scope"] = Scopes.OpenId,
            ["state"] = Guid.NewGuid().ToString("N"),
            ["nonce"] = Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = CodeChallengeMethods.S256,
            ["max_age"] = "3600",
            ["ui_locales"] = "en-US fr-FR",
            ["claims"] = """{"userinfo":{"email":{"essential":true}}}""",
            ["resource"] = TestConstants.ApiResource,
        };

        var code = await client.AuthorizeGetCallbackAsync(OidcFlows.Endpoint(discovery, "authorization_endpoint"), query, "code");
        Assert.False(string.IsNullOrEmpty(code));

        // The code is real and redeemable — closes the loop that the bound request produced a usable grant.
        var token = await client.ExchangeCodeAsync(discovery, code, verifier, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);
        Assert.NotNull(token["access_token"]);
    }

    [Fact]
    public async Task Userinfo_binds_access_token_from_query_and_from_bearer_header()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var accessToken = (await OidcFlows.AuthCodeTokensViaParAsync(
            client, discovery, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret))
            ["access_token"]!.GetValue<string>();
        var userInfoEndpoint = OidcFlows.Endpoint(discovery, "userinfo_endpoint");

        // OIDC Core 5.3.1: the access token may be presented as the access_token request parameter. This is the
        // query branch of the generated UserInfoRequest.BindAsync (SupportsGet -> RequestValues(query, form)).
        var viaQuery = await OidcFlows.GetJsonAsync(
            client, OidcFlows.BuildQuery(userInfoEndpoint, new Dictionary<string, string> { ["access_token"] = accessToken }));
        Assert.False(string.IsNullOrEmpty(viaQuery["sub"]?.GetValue<string>()));

        // OIDC Core 5.3.1 RECOMMENDED form: the access token in the Authorization: Bearer header.
        using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        var headerResponse = await client.SendAsync(request, TestContext.Current.CancellationToken);
        headerResponse.EnsureSuccessStatusCode();
        var viaHeader = JsonNode.Parse(
            await headerResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(viaQuery["sub"]!.GetValue<string>(), viaHeader["sub"]!.GetValue<string>());
    }

    [Fact]
    public async Task Endsession_get_binds_id_token_hint_and_redirects_to_registered_post_logout_uri()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var idToken = (await OidcFlows.AuthCodeTokensViaParAsync(
            client, discovery, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret))
            ["id_token"]!.GetValue<string>();

        // GET /endsession binding the SupportsGet EndSessionRequest: id_token_hint (string), post_logout_redirect_uri
        // (Uri) and ui_locales (culture list) from the query. With a valid hint and a registered post-logout URI the
        // RP-initiated logout redirects back to that URI.
        var query = new Dictionary<string, string>
        {
            ["id_token_hint"] = idToken,
            ["post_logout_redirect_uri"] = MinimalApiTestConstants.PostLogoutRedirectUri,
            ["ui_locales"] = "en-US",
            ["confirmed"] = "true",
        };
        var response = await client.GetAsync(
            OidcFlows.BuildQuery(OidcFlows.Endpoint(discovery, "end_session_endpoint"), query),
            TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found,
            $"/endsession returned {(int)response.StatusCode}, expected a redirect to the post-logout URI");
        Assert.StartsWith(MinimalApiTestConstants.PostLogoutRedirectUri, response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Device_authorization_request_returns_device_and_user_codes()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        // RFC 8628: a confidential client (ClientSecretPost) starts the device grant. Binds the generated
        // DeviceAuthorizationRequest + ClientRequest from the posted form. This is also the regression guard for the
        // core bug where IDeviceAuthorizationHandler was unregistered and the endpoint mis-inferred a [FromBody] 415.
        var response = await client.PostFormJsonAsync(OidcFlows.Endpoint(discovery, "device_authorization_endpoint"),
            new Dictionary<string, string>
            {
                ["client_id"] = TestConstants.ConfidentialClientId,
                ["client_secret"] = TestConstants.ConfidentialClientSecret,
                ["scope"] = Scopes.OpenId,
            });

        Assert.False(string.IsNullOrEmpty(response["device_code"]?.GetValue<string>()));
        Assert.False(string.IsNullOrEmpty(response["user_code"]?.GetValue<string>()));
        Assert.False(string.IsNullOrEmpty(response["verification_uri"]?.GetValue<string>()));
        Assert.NotNull(response["expires_in"]);
    }

    [Fact]
    public async Task Dynamic_client_registration_lifecycle_register_read_update_delete()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var registrationEndpoint = OidcFlows.Endpoint(discovery, "registration_endpoint");

        // REGISTER (RFC 7591): JSON body via native [FromBody], not a form. The host runs open DCR
        // (RequireInitialAccessToken=false), so no initial access token is needed.
        var (registered, registerResponse) = await PostJsonAsync(client, registrationEndpoint, new JsonObject
        {
            ["redirect_uris"] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { ResponseTypes.Code },
            ["token_endpoint_auth_method"] = "client_secret_basic",
            ["client_name"] = "Lifecycle Test Client",
        }, HttpStatusCode.Created);

        var clientId = registered["client_id"]!.GetValue<string>();
        var registrationAccessToken = registered["registration_access_token"]!.GetValue<string>();
        var registrationClientUri = registered["registration_client_uri"]!.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(clientId));
        Assert.False(string.IsNullOrEmpty(registrationAccessToken));
        // The 201 uses Results.Json, not Results.Created, so the management URL is in the body, not a Location header.
        Assert.Null(registerResponse.Headers.Location);
        Assert.False(string.IsNullOrEmpty(registrationClientUri));

        // READ (RFC 7592 §2.1): the registration_access_token authenticates as Bearer against the management URL.
        var read = await SendWithBearerAsync(client, HttpMethod.Get, registrationClientUri, registrationAccessToken);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        var readBody = JsonNode.Parse(
            await read.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(clientId, readBody["client_id"]!.GetValue<string>());

        // UPDATE (RFC 7592 §2.2): PUT the full metadata with a changed client_name.
        var updateBody = new JsonObject
        {
            ["client_id"] = clientId,
            ["redirect_uris"] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { ResponseTypes.Code },
            ["token_endpoint_auth_method"] = "client_secret_basic",
            ["client_name"] = "Renamed Client",
        };
        if (registered["client_secret"]?.GetValue<string>() is { } secret)
            updateBody["client_secret"] = secret;
        var update = await SendWithBearerAsync(
            client, HttpMethod.Put, registrationClientUri, registrationAccessToken, updateBody);
        Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        var updated = JsonNode.Parse(
            await update.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

        // RFC 7592 §3 permits the server to rotate the registration_access_token on update; the management
        // operations that follow must use the most recently issued one.
        var manageToken = updated["registration_access_token"]?.GetValue<string>() ?? registrationAccessToken;

        // DELETE (RFC 7592 §2.3): 204 No Content.
        var delete = await SendWithBearerAsync(client, HttpMethod.Delete, registrationClientUri, manageToken);
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
    }

    private static async Task<(JsonObject Body, HttpResponseMessage Response)> PostJsonAsync(
        HttpClient client, string url, JsonObject body, HttpStatusCode expected)
    {
        var response = await client.PostAsync(url, JsonContent.Create(body), TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == expected, $"POST {url} -> {(int)response.StatusCode}: {raw}");
        return (JsonNode.Parse(raw)!.AsObject(), response);
    }

    private static async Task<HttpResponseMessage> SendWithBearerAsync(
        HttpClient client, HttpMethod method, string url, string bearer, JsonObject? jsonBody = null)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, bearer);
        if (jsonBody is not null)
            request.Content = JsonContent.Create(jsonBody);
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }
}
