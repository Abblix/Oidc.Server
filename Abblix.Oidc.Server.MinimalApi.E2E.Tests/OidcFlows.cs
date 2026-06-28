// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Xunit;

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
        var par = await client.PostFormJsonAsync(Endpoint(discovery, "pushed_authorization_request_endpoint"), form);
        return par["request_uri"]!.GetValue<string>();
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
            new("client_id", clientId),
            new("client_secret", clientSecret),
            new("response_type", ResponseTypes.Code),
            new("redirect_uri", TestConstants.RedirectUri),
            new("scope", Scopes.OpenId),
            new("state", Guid.NewGuid().ToString("N")),
            new("nonce", Guid.NewGuid().ToString("N")),
            new("code_challenge", challenge),
            new("code_challenge_method", CodeChallengeMethods.S256),
        };
        if (extraAuthorizeParams is not null)
            parForm.AddRange(extraAuthorizeParams);

        var requestUri = await client.PushAuthorizationRequestAsync(discovery, parForm);
        var code = await client.AuthorizeGetCallbackAsync(Endpoint(discovery, "authorization_endpoint"),
            new Dictionary<string, string> { ["client_id"] = clientId, ["request_uri"] = requestUri }, "code");
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
        => await client.PostFormJsonAsync(Endpoint(discovery, "token_endpoint"), new Dictionary<string, string>
        {
            ["grant_type"] = GrantTypes.AuthorizationCode,
            ["code"] = code,
            ["redirect_uri"] = TestConstants.RedirectUri,
            ["code_verifier"] = verifier,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
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
