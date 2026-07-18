// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

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
        BaseAddress = TestFactory.BaseAddress,
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
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.MaxAge] = "3600",
            [AuthorizationRequest.Parameters.UiLocales] = "en-US fr-FR",
            [AuthorizationRequest.Parameters.Claims] = """{"userinfo":{"email":{"essential":true}}}""",
            [AuthorizationRequest.Parameters.Resource] = TestConstants.ApiResource,
        };

        var code = await client.AuthorizeGetCallbackAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint), query, ResponseParameters.Code);
        Assert.False(string.IsNullOrEmpty(code));

        // The code is real and redeemable - closes the loop that the bound request produced a usable grant.
        var token = await client.ExchangeCodeAsync(discovery, code, verifier, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);
        Assert.NotNull(token[ResponseParameters.AccessToken]);
    }

    [Fact]
    public async Task Userinfo_binds_access_token_from_query_and_from_bearer_header()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var accessToken = (await OidcFlows.AuthCodeTokensViaParAsync(
            client, discovery, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret))
            [ResponseParameters.AccessToken]!.GetValue<string>();
        var userInfoEndpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.UserInfoEndpoint);

        // OIDC Core 5.3.1: the access token may be presented as the access_token request parameter. This is the
        // query branch of the generated UserInfoRequest.BindAsync (SupportsGet -> RequestValues(query, form)).
        var viaQuery = await OidcFlows.GetJsonAsync(
            client, OidcFlows.BuildQuery(userInfoEndpoint, new Dictionary<string, string> { [UserInfoRequest.Parameters.AccessToken] = accessToken }));
        Assert.False(string.IsNullOrEmpty(viaQuery[IanaClaimTypes.Sub]?.GetValue<string>()));

        // OIDC Core 5.3.1 RECOMMENDED form: the access token in the Authorization: Bearer header.
        using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        var headerResponse = await client.SendAsync(request, TestContext.Current.CancellationToken);
        headerResponse.EnsureSuccessStatusCode();
        var viaHeader = JsonNode.Parse(
            await headerResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(viaQuery[IanaClaimTypes.Sub]!.GetValue<string>(), viaHeader[IanaClaimTypes.Sub]!.GetValue<string>());
    }

    [Fact]
    public async Task Endsession_get_binds_id_token_hint_and_redirects_to_registered_post_logout_uri()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var idToken = (await OidcFlows.AuthCodeTokensViaParAsync(
            client, discovery, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret))
            [ResponseParameters.IdToken]!.GetValue<string>();

        // GET /endsession binding the SupportsGet EndSessionRequest: id_token_hint (string), post_logout_redirect_uri
        // (Uri) and ui_locales (culture list) from the query. With a valid hint and a registered post-logout URI the
        // RP-initiated logout redirects back to that URI.
        var query = new Dictionary<string, string>
        {
            [EndSessionRequest.Parameters.IdTokenHint] = idToken,
            [EndSessionRequest.Parameters.PostLogoutRedirectUri] = MinimalApiTestConstants.PostLogoutRedirectUri,
            [EndSessionRequest.Parameters.UiLocales] = "en-US",
            ["confirmed"] = "true",
        };
        var response = await client.GetAsync(
            OidcFlows.BuildQuery(OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.EndSessionEndpoint), query),
            TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
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
        var response = await client.PostFormJsonAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.DeviceAuthorizationEndpoint),
            new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
                [DeviceAuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            });

        Assert.False(string.IsNullOrEmpty(response[DeviceAuthorizationResponse.Parameters.DeviceCode]?.GetValue<string>()));
        Assert.False(string.IsNullOrEmpty(response[DeviceAuthorizationResponse.Parameters.UserCode]?.GetValue<string>()));
        Assert.False(string.IsNullOrEmpty(response["verification_uri"]?.GetValue<string>()));
        Assert.NotNull(response[DeviceAuthorizationResponse.Parameters.ExpiresIn]);
    }

    [Fact]
    public async Task Dynamic_client_registration_lifecycle_register_read_update_delete()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var registrationEndpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.RegistrationEndpoint);

        // REGISTER (RFC 7591): JSON body via native [FromBody], not a form. The host runs open DCR
        // (RequireInitialAccessToken=false), so no initial access token is needed.
        var (registered, registerResponse) = await PostJsonAsync(client, registrationEndpoint, new JsonObject
        {
            [ClientRegistrationRequest.Parameters.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [ClientRegistrationRequest.Parameters.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [ClientRegistrationRequest.Parameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [ClientRegistrationRequest.Parameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
            [ClientRegistrationRequest.Parameters.ClientName] = "Lifecycle Test Client",
        }, HttpStatusCode.Created);

        var clientId = registered[ClientRequest.Parameters.ClientId]!.GetValue<string>();
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
        Assert.Equal(clientId, readBody[ClientRequest.Parameters.ClientId]!.GetValue<string>());

        // UPDATE (RFC 7592 §2.2): PUT the full metadata with a changed client_name.
        var updateBody = new JsonObject
        {
            [ClientRequest.Parameters.ClientId] = clientId,
            [ClientRegistrationRequest.Parameters.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [ClientRegistrationRequest.Parameters.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [ClientRegistrationRequest.Parameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [ClientRegistrationRequest.Parameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
            [ClientRegistrationRequest.Parameters.ClientName] = "Renamed Client",
        };
        if (registered[ClientRequest.Parameters.ClientSecret]?.GetValue<string>() is { } secret)
            updateBody[ClientRequest.Parameters.ClientSecret] = secret;
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

    [Theory]
    [InlineData(AuthorizationRequest.Parameters.Claims, "{not valid json")]
    [InlineData(AuthorizationRequest.Parameters.MaxAge, "9999999999999999")]
    [InlineData(AuthorizationRequest.Parameters.UiLocales, "!")]
    public async Task Malformed_special_format_query_param_is_a_400_not_a_500(string parameter, string badValue)
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (_, challenge) = OidcFlows.Pkce();

        // A well-formed base request plus one hostile special-format field.
        var query = new Dictionary<string, string>
        {
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [parameter] = badValue,
        };
        var url = OidcFlows.BuildQuery(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint), query);

        // Under TestServer a BindAsync throw does not translate to an HTTP status - it propagates out of the awaited
        // call. Pre-fix the converter throws JsonException / CultureNotFoundException / TimeSpan overflow; post-fix
        // FormValues shapes every one into a BadHttpRequestException carrying the 400 the MVC binder would have
        // produced. Asserting the thrown type is the genuine red (wrong exception) to green (BadHttpRequestException).
        var ex = await Assert.ThrowsAsync<BadHttpRequestException>(
            () => client.GetAsync(url, TestContext.Current.CancellationToken));
        Assert.Equal(StatusCodes.Status400BadRequest, ex.StatusCode);
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
