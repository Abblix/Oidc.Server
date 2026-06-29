// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Shared flow helpers for driving the Minimal API test host as a non-interactive RP: discovery, PKCE, form posts,
/// PAR, /authorize (query or PAR), code exchange, dynamic client registration and JWT decoding. Centralised so each
/// scenario file reads as a sequence of intent, not HTTP plumbing.
/// </summary>
internal static class OidcFlows
{
    public static async Task<JsonObject> FetchDiscoveryAsync(this HttpClient client, string prefix = "")
        => await client.GetJsonAsync($"{prefix}/.well-known/openid-configuration");

    public static async Task<JsonObject> GetJsonAsync(this HttpClient client, string url)
    {
        var raw = await client.GetStringAsync(url, TestContext.Current.CancellationToken);
        return JsonNode.Parse(raw)!.AsObject();
    }

    public static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    public static Task<HttpResponseMessage> PostFormAsync(
        this HttpClient client,
        string endpoint,
        IEnumerable<KeyValuePair<string, string>> form)
        => client.PostAsync(endpoint, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

    public static async Task<JsonObject> PostFormJsonAsync(
        this HttpClient client,
        string endpoint,
        IEnumerable<KeyValuePair<string, string>> form)
    {
        var response = await client.PostFormAsync(endpoint, form);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"POST {endpoint} failed: {(int)response.StatusCode} {raw}");
        return JsonNode.Parse(raw)!.AsObject();
    }

    public static string Endpoint(JsonObject discovery, string key) => discovery[key]!.GetValue<string>();

    /// <summary>Builds <paramref name="baseUrl"/> with a query string, preserving repeated keys (e.g. multiple
    /// <c>resource</c> values) so the generated <c>Uri[]</c> binding can be exercised.</summary>
    public static string BuildQuery(string baseUrl, IEnumerable<KeyValuePair<string, string>> query)
    {
        var pairs = query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}");
        return $"{baseUrl}?{string.Join('&', pairs)}";
    }

    /// <summary>Drives a GET /authorize and returns the value of a callback query parameter (e.g. <c>code</c> or
    /// <c>response</c>), asserting the server redirected back to the client.</summary>
    public static async Task<string> AuthorizeGetCallbackAsync(
        this HttpClient client,
        string authorizeEndpoint,
        IEnumerable<KeyValuePair<string, string>> query,
        string param)
    {
        var response = await client.GetAsync(
            BuildQuery(authorizeEndpoint, query), TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found,
            $"/authorize returned {(int)response.StatusCode}, expected redirect");
        var location = response.Headers.Location
            ?? throw new InvalidOperationException("/authorize did not set Location");
        return HttpUtility.ParseQueryString(location.Query)[param]
            ?? throw new InvalidOperationException($"No '{param}' in callback: {location}");
    }

    /// <summary>Pushes an authorization request (RFC 9126) and returns the issued <c>request_uri</c>.</summary>
    public static async Task<string> PushAuthorizationRequestAsync(
        this HttpClient client,
        JsonObject discovery,
        IEnumerable<KeyValuePair<string, string>> form)
    {
        var par = await client.PostFormJsonAsync(
            Endpoint(discovery, ConfigurationResponse.Parameters.PushedAuthorizationRequestEndpoint), form);
        return par[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();
    }

    /// <summary>
    /// Drives the full PAR -> /authorize -> /token code flow for the given client and returns the token response.
    /// The auto-auth / auto-consent stubs make /authorize a non-interactive redirect carrying the code. Extra
    /// authorize parameters (e.g. RAR <c>authorization_details</c> or a <c>resource</c>) are merged into the PAR form.
    /// </summary>
    public static async Task<JsonObject> AuthCodeTokensViaParAsync(
        this HttpClient client,
        JsonObject discovery,
        string clientId,
        string clientSecret,
        IEnumerable<KeyValuePair<string, string>>? extraAuthorizeParams = null)
    {
        var (verifier, challenge) = Pkce();
        var parForm = new List<KeyValuePair<string, string>>
        {
            new(ClientRequest.Parameters.ClientId, clientId),
            new(ClientRequest.Parameters.ClientSecret, clientSecret),
            new(AuthorizationRequest.Parameters.ResponseType, ResponseTypes.Code),
            new(AuthorizationRequest.Parameters.RedirectUri, TestConstants.RedirectUri),
            new(AuthorizationRequest.Parameters.Scope, Scopes.OpenId),
            new(AuthorizationRequest.Parameters.State, Guid.NewGuid().ToString("N")),
            new(AuthorizationRequest.Parameters.Nonce, Guid.NewGuid().ToString("N")),
            new(AuthorizationRequest.Parameters.CodeChallenge, challenge),
            new(AuthorizationRequest.Parameters.CodeChallengeMethod, CodeChallengeMethods.S256),
        };
        if (extraAuthorizeParams is not null)
            parForm.AddRange(extraAuthorizeParams);

        var requestUri = await client.PushAuthorizationRequestAsync(discovery, parForm);
        var code = await client.AuthorizeGetCallbackAsync(
            Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint),
            new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = clientId,
                [AuthorizationRequest.Parameters.RequestUri] = requestUri,
            },
            ResponseParameters.Code);
        return await client.ExchangeCodeAsync(discovery, code, verifier, clientId, clientSecret);
    }

    /// <summary>Exchanges an authorization code for tokens at the token endpoint.</summary>
    public static async Task<JsonObject> ExchangeCodeAsync(
        this HttpClient client,
        JsonObject discovery,
        string code,
        string verifier,
        string clientId,
        string clientSecret)
        => await client.PostFormJsonAsync(
            Endpoint(discovery, ConfigurationResponse.Parameters.TokenEndpoint),
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = code,
                [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [TokenRequest.Parameters.CodeVerifier] = verifier,
                [ClientRequest.Parameters.ClientId] = clientId,
                [ClientRequest.Parameters.ClientSecret] = clientSecret,
            });

    public static JsonObject DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        var json = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        return JsonNode.Parse(json)!.AsObject();
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }
}
