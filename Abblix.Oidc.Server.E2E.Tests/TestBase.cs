// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// Helpers for driving the test OIDC host as a non-interactive RP:
/// discovery, DCR, PAR, /authorize, /token, and JWT decoding. Mirrors
/// the shape of the AuthenticationService.ConformanceTests TestBase so
/// scenario files read the same way.
/// </summary>
[Collection(TestCollection.Name)]
public abstract class TestBase(TestFactory factory)
{
    /// <summary>
    /// OAuth 2.0 / OIDC / RAR wire parameter names. Centralised so scenarios and
    /// helpers don't sprinkle literal strings (Sonar S1192) and a rename surfaces
    /// in one place.
    /// </summary>
    protected static class WireParameters
    {
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string ResponseType = "response_type";
        public const string RedirectUri = "redirect_uri";
        public const string Scope = "scope";
        public const string State = "state";
        public const string Nonce = "nonce";
        public const string CodeChallenge = "code_challenge";
        public const string CodeChallengeMethod = "code_challenge_method";
        public const string CodeVerifier = "code_verifier";
        public const string GrantType = "grant_type";
        public const string Code = "code";
        public const string RequestUri = "request_uri";
        public const string RefreshToken = "refresh_token";
        public const string Error = "error";
        public const string AuthorizationDetails = "authorization_details";
        public const string AccessToken = "access_token";
    }

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "TestServer in-memory base address; not a deployment URL.")]
    protected HttpClient CreateClient()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost"),
        });
        return client;
    }

    protected static async Task<DiscoveryDocument> FetchDiscoveryAsync(HttpClient client)
    {
        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
        var doc = await response.Content.ReadFromJsonAsync<DiscoveryDocument>();
        Assert.NotNull(doc);
        return doc!;
    }

    protected static async Task<JsonObject> RegisterClientAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        JsonObject body)
    {
        Assert.NotNull(discovery.RegistrationEndpoint);
        var response = await client.PostAsJsonAsync(discovery.RegistrationEndpoint!, body);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"DCR failed: {(int)response.StatusCode} {raw}");
        var parsed = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(parsed);
        return parsed!;
    }

    protected static async Task<JsonObject> PushAuthorizationRequestAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        IEnumerable<KeyValuePair<string, string>> form)
    {
        Assert.NotNull(discovery.PushedAuthorizationRequestEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.PushedAuthorizationRequestEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        var response = await client.SendAsync(request);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"PAR failed: {(int)response.StatusCode} {raw}");
        var parsed = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(parsed);
        return parsed!;
    }

    protected static async Task<string> AuthorizeAndExtractCodeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Dictionary<string, string> queryParams)
    {
        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, queryParams);
        var response = await client.GetAsync(uri);
        // Auto-redirect is disabled — the success terminal is a 302 back to redirect_uri
        // with code in the query string.
        Assert.True(
            response.StatusCode is System.Net.HttpStatusCode.Redirect or System.Net.HttpStatusCode.Found,
            $"/authorize returned {(int)response.StatusCode}, expected redirect. Body: {await response.Content.ReadAsStringAsync()}");
        var location = response.Headers.Location ?? throw new InvalidOperationException("/authorize did not set Location header");
        var query = System.Web.HttpUtility.ParseQueryString(location.Query);
        var code = query[WireParameters.Code] ?? throw new InvalidOperationException($"No code in callback URI: {location}");
        return code;
    }

    /// <summary>
    /// Drives /authorize and asserts the AS redirected back to <c>redirect_uri</c> with an
    /// <c>error</c> query parameter (the OAuth 2.0 error-response shape). Returns that error
    /// code -- callers assert on its value (e.g. <c>access_denied</c>).
    /// </summary>
    protected static async Task<string> AuthorizeAndExtractErrorAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Dictionary<string, string> queryParams)
    {
        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, queryParams);
        var response = await client.GetAsync(uri);
        Assert.True(
            response.StatusCode is System.Net.HttpStatusCode.Redirect or System.Net.HttpStatusCode.Found,
            $"/authorize returned {(int)response.StatusCode}, expected redirect. Body: {await response.Content.ReadAsStringAsync()}");
        var location = response.Headers.Location ?? throw new InvalidOperationException("/authorize did not set Location header");
        var query = System.Web.HttpUtility.ParseQueryString(location.Query);
        return query[WireParameters.Error] ?? throw new InvalidOperationException($"No error in callback URI: {location}");
    }

    protected static async Task<JsonObject> ExchangeCodeForTokensAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        IEnumerable<KeyValuePair<string, string>> form)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        var response = await client.SendAsync(request);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"/token failed: {(int)response.StatusCode} {raw}");
        var parsed = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(parsed);
        return parsed!;
    }

    protected static JsonObject DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.True(parts.Length == 3, "JWT must have 3 segments");
        var payload = Base64UrlDecode(parts[1]);
        var parsed = JsonNode.Parse(payload)?.AsObject();
        Assert.NotNull(parsed);
        return parsed!;
    }

    /// <summary>
    /// Drives PAR -> /authorize -> /token for the supplied client and
    /// authorization_details payload. Returns the parsed token response
    /// JsonObject. Throws on any non-success HTTP status — use the
    /// lower-level helpers for negative scenarios.
    /// </summary>
    protected async Task<JsonObject> PerformParFlowAsync(
        string clientId,
        string clientSecret,
        string redirectUri,
        string authorizationDetailsWireJson,
        string scope = "openid")
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();

        var parResponse = await PushAuthorizationRequestAsync(client, discovery, new Dictionary<string, string>
        {
            [WireParameters.ClientId] = clientId,
            [WireParameters.ClientSecret] = clientSecret,
            [WireParameters.ResponseType] = "code",
            [WireParameters.RedirectUri] = redirectUri,
            [WireParameters.Scope] = scope,
            [WireParameters.State] = Guid.NewGuid().ToString("N"),
            [WireParameters.Nonce] = Guid.NewGuid().ToString("N"),
            [WireParameters.CodeChallenge] = challenge,
            [WireParameters.CodeChallengeMethod] = "S256",
            [WireParameters.AuthorizationDetails] = authorizationDetailsWireJson,
        });
        var requestUri = parResponse[WireParameters.RequestUri]?.GetValue<string>()
            ?? throw new InvalidOperationException("PAR did not return request_uri");

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [WireParameters.ClientId] = clientId,
            [WireParameters.RequestUri] = requestUri,
        });

        return await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [WireParameters.GrantType] = "authorization_code",
            [WireParameters.Code] = code,
            [WireParameters.RedirectUri] = redirectUri,
            [WireParameters.CodeVerifier] = verifier,
            [WireParameters.ClientId] = clientId,
            [WireParameters.ClientSecret] = clientSecret,
        });
    }

    /// <summary>
    /// Submits a PAR request and returns the raw HTTP response (without
    /// asserting success). Use when a negative test expects PAR itself
    /// to fail (e.g. allowlist enforcement).
    /// </summary>
    protected async Task<HttpResponseMessage> PushAuthorizationRequestRawAsync(
        IEnumerable<KeyValuePair<string, string>> form)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.PushedAuthorizationRequestEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        return await client.SendAsync(request);
    }

    /// <summary>
    /// Negative-test helper: builds a PAR submission with the boilerplate
    /// pre-filled, sends it, and asserts the AS responded with
    /// <c>invalid_authorization_details</c>. The supplied
    /// <paramref name="authorizationDetailsWireJson"/> is the only
    /// variable across all rejection scenarios.
    /// </summary>
    protected async Task AssertParRejectedWithInvalidAuthorizationDetailsAsync(
        string clientId,
        string authorizationDetailsWireJson)
    {
        var (_, challenge) = GeneratePkcePair();
        var response = await PushAuthorizationRequestRawAsync(new Dictionary<string, string>
        {
            [WireParameters.ClientId] = clientId,
            [WireParameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [WireParameters.ResponseType] = "code",
            [WireParameters.RedirectUri] = TestConstants.RedirectUri,
            [WireParameters.Scope] = "openid",
            [WireParameters.CodeChallenge] = challenge,
            [WireParameters.CodeChallengeMethod] = "S256",
            [WireParameters.AuthorizationDetails] = authorizationDetailsWireJson,
        });

        var raw = await response.Content.ReadAsStringAsync();
        Assert.False(response.IsSuccessStatusCode,
            $"Expected error response but got {(int)response.StatusCode}: {raw}");
        var body = JsonNode.Parse(raw)?.AsObject();
        var errorCode = body?[WireParameters.Error]?.GetValue<string>();
        Assert.Equal("invalid_authorization_details", errorCode);
    }

    protected static (string Verifier, string Challenge) GeneratePkcePair()
    {
        var verifierBytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64UrlEncode(verifierBytes);
        var challengeBytes = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Base64UrlEncode(challengeBytes);
        return (verifier, challenge);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}

internal static class QueryHelpers
{
    public static Uri BuildUri(string baseUri, IEnumerable<KeyValuePair<string, string>> queryParams)
    {
        var builder = new UriBuilder(baseUri);
        var query = string.Join('&', queryParams
            .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        builder.Query = string.IsNullOrEmpty(builder.Query)
            ? query
            : builder.Query.TrimStart('?') + "&" + query;
        return builder.Uri;
    }
}
