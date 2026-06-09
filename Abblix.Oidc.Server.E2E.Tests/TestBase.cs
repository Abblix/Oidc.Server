// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// Helpers for driving the test OIDC host as a non-interactive RP:
/// discovery, DCR, PAR, /authorize, /token, and JWT decoding. Mirrors
/// the shape of the AuthenticationService.ConformanceTests TestBase so
/// scenario files read the same way.
/// </summary>
public abstract class TestBase(TestFactory factory)
{
    protected HttpClient CreateClient()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        return client;
    }

    protected static async Task<DiscoveryDocument> FetchDiscoveryAsync(HttpClient client)
    {
        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
        var doc = await response.Content.ReadFromJsonAsync<DiscoveryDocument>();
        Assert.NotNull(doc);
        return doc;
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
        return parsed;
    }

    protected static async Task<JsonObject> PushAuthorizationRequestAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        IEnumerable<KeyValuePair<string, string>> form)
    {
        Assert.NotNull(discovery.PushedAuthorizationRequestEndpoint);
        var response = await FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, form);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"PAR failed: {(int)response.StatusCode} {raw}");
        var parsed = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(parsed);
        return parsed;
    }

    protected static async Task<string> AuthorizeAndExtractCodeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Dictionary<string, string> queryParams) =>
        await AuthorizeAndExtractFromCallbackAsync(
            client, discovery, queryParams, TokenRequest.Parameters.Code);

    /// <summary>
    /// Drives /authorize and asserts the AS redirected back to <c>redirect_uri</c> with an
    /// <c>error</c> query parameter (the OAuth 2.0 error-response shape). Returns that error
    /// code -- callers assert on its value (e.g. <c>access_denied</c>).
    /// </summary>
    protected static async Task<string> AuthorizeAndExtractErrorAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Dictionary<string, string> queryParams) =>
        await AuthorizeAndExtractFromCallbackAsync(client, discovery, queryParams, "error");

    /// <summary>
    /// Drives /authorize for a JARM (JWT Secured Authorization Response Mode) request and returns the value of
    /// the single <c>response</c> callback parameter — the signed (and optionally encrypted) response JWT.
    /// </summary>
    protected static async Task<string> AuthorizeAndExtractResponseJwtAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Dictionary<string, string> queryParams) =>
        await AuthorizeAndExtractFromCallbackAsync(client, discovery, queryParams, "response");

    /// <summary>
    /// Drives /authorize, asserts the AS responded with a 302/303 back to <c>redirect_uri</c>,
    /// and returns the value of the requested callback-URI query parameter. Shared body of
    /// <see cref="AuthorizeAndExtractCodeAsync"/> and <see cref="AuthorizeAndExtractErrorAsync"/>.
    /// </summary>
    private static async Task<string> AuthorizeAndExtractFromCallbackAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Dictionary<string, string> queryParams,
        string paramName)
    {
        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, queryParams);
        var response = await client.GetAsync(uri);
        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found,
            $"/authorize returned {(int)response.StatusCode}, expected redirect. Body: {await response.Content.ReadAsStringAsync()}");
        var location = response.Headers.Location ?? throw new InvalidOperationException("/authorize did not set Location header");
        var query = System.Web.HttpUtility.ParseQueryString(location.Query);
        return query[paramName] ?? throw new InvalidOperationException($"No '{paramName}' in callback URI: {location}");
    }

    protected static async Task<JsonObject> ExchangeCodeForTokensAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        IEnumerable<KeyValuePair<string, string>> form)
    {
        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"/token failed: {(int)response.StatusCode} {raw}");
        var parsed = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(parsed);
        return parsed;
    }

    protected static JsonObject DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.True(parts.Length == 3, "JWT must have 3 segments");

        var payload = Base64UrlDecode(parts[1]);
        var parsed = JsonNode.Parse(payload)?.AsObject();
        Assert.NotNull(parsed);

        return parsed;
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
        string scope = Scopes.OpenId,
        HttpClient? client = null)
    {
        client ??= CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();

        var parResponse = await PushAuthorizationRequestAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = redirectUri,
            [AuthorizationRequest.Parameters.Scope] = scope,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.AuthorizationDetails] = authorizationDetailsWireJson,
        });
        var requestUri = parResponse[AuthorizationRequest.Parameters.RequestUri]?.GetValue<string>()
            ?? throw new InvalidOperationException("PAR did not return request_uri");

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });

        return await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = redirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        });
    }

    /// <summary>
    /// Submits a PAR request and returns the raw HTTP response (without
    /// asserting success). Use when a negative test expects PAR itself
    /// to fail (e.g. allowlist enforcement).
    /// </summary>
    private async Task<HttpResponseMessage> PushAuthorizationRequestRawAsync(
        IEnumerable<KeyValuePair<string, string>> form)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        return await FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, form);
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
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.AuthorizationDetails] = authorizationDetailsWireJson,
        });

        var raw = await response.Content.ReadAsStringAsync();
        Assert.False(response.IsSuccessStatusCode,
            $"Expected error response but got {(int)response.StatusCode}: {raw}");
        var body = JsonNode.Parse(raw)?.AsObject();
        var errorCode = body?["error"]?.GetValue<string>();
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, errorCode);
    }

    internal static (string Verifier, string Challenge) GeneratePkcePair()
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
