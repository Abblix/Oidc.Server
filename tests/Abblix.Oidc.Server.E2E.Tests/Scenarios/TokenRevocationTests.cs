// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the token revocation endpoint (RFC 7009) against the real endpoint and the real token
/// registry.
/// </summary>
/// <remarks>
/// Revocation is the control an operator or a user reaches for after a device is lost or a token leaks, so the
/// property that matters is not the shape of the response but whether the token stops working afterwards. A
/// revocation endpoint that answers 200 and leaves the token usable is worse than none at all: it reports that
/// the danger has been dealt with.
///
/// The suite previously exercised revocation only as a side effect of reuse detection, which revokes a family
/// on its own initiative. Nothing walked the endpoint a client actually calls.
/// </remarks>
public class TokenRevocationTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task A_revoked_refresh_token_can_no_longer_be_redeemed()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();

        // Proving it works first: otherwise a test that only checks the token fails afterwards would pass
        // just as happily against a token that never worked at all.
        var beforeRevocation = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(beforeRevocation.IsSuccessStatusCode);
        var rotated = (await ReadJsonAsync(beforeRevocation))[TokenResponse.Parameters.RefreshToken]!
            .GetValue<string>();

        var revocation = await RevokeAsync(client, discovery, rotated);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        var afterRevocation = await RefreshAsync(client, discovery, rotated);
        await AssertInvalidGrantAsync(afterRevocation);
    }

    [Fact]
    public async Task Revoking_a_token_that_was_never_issued_still_answers_success()
    {
        // RFC 7009 Section 2.2 requires 200 for a token the server does not recognize. The reason is not
        // politeness: a distinguishable answer turns the endpoint into an oracle that tells an attacker
        // whether a guessed token exists, which is the one thing this endpoint must never reveal.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var response = await RevokeAsync(client, discovery, "a-token-this-server-never-issued");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Revocation_requires_the_client_to_authenticate()
    {
        // Without client authentication anyone holding a token could revoke it, and anyone able to guess one
        // could try. That turns a security control into a denial-of-service lever against other clients.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.RevocationEndpoint!,
            new Dictionary<string, string> { [RevocationRequest.Parameters.Token] = refreshToken });

        // OAuth 2.1 section 3.2.4: a client authenticating without HTTP Basic, and not registered for it, is owed no
        // challenge, so the endpoint answers invalid_client with its own status
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // The token survives the unauthenticated attempt, which is the half that matters: a rejected request
        // that revoked anyway would be the denial of service this check exists to prevent.
        var stillWorks = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(stillWorks.IsSuccessStatusCode);
    }

    [Fact]
    public async Task The_revocation_endpoint_is_published_in_discovery()
    {
        // A client finds this endpoint through discovery, so an endpoint that is enabled but unadvertised is
        // unreachable in practice.
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.RevocationEndpoint);
    }

    /// <summary>
    /// RFC 8414 section 2 reads an omitted <c>revocation_endpoint_auth_methods_supported</c> as client_secret_basic
    /// alone, which would tell a public client it cannot revoke its tokens. The endpoint authenticates as the token
    /// endpoint does, so it publishes the same methods, and the assertion algorithms the section requires beside a
    /// JWT-based one.
    /// </summary>
    [Fact]
    public async Task Discovery_names_the_methods_the_revocation_endpoint_accepts()
    {
        var document = await FetchDiscoveryJsonAsync(CreateClient());

        var tokenMethods = Strings(document, ConfigurationResponse.Parameters.TokenEndpointAuthMethodsSupported);
        var revocationMethods = Strings(document, ConfigurationResponse.Parameters.RevocationEndpointAuthMethodsSupported);
        Assert.Equal(tokenMethods, revocationMethods);
        Assert.Contains(ClientAuthenticationMethods.None, revocationMethods);
        Assert.Equal(
            Strings(document, ConfigurationResponse.Parameters.TokenEndpointAuthSigningAlgValuesSupported),
            Strings(document, ConfigurationResponse.Parameters.RevocationEndpointAuthSigningAlgValuesSupported));
    }

    /// <summary>
    /// The introspection endpoint refuses a client authenticating with none, so it publishes every method of the
    /// token endpoint but that one.
    /// </summary>
    [Fact]
    public async Task Discovery_names_the_methods_the_introspection_endpoint_accepts()
    {
        var document = await FetchDiscoveryJsonAsync(CreateClient());

        var tokenMethods = Strings(document, ConfigurationResponse.Parameters.TokenEndpointAuthMethodsSupported);
        Assert.Equal(
            tokenMethods.Where(method => method != ClientAuthenticationMethods.None),
            Strings(document, ConfigurationResponse.Parameters.IntrospectionEndpointAuthMethodsSupported));
        Assert.Equal(
            Strings(document, ConfigurationResponse.Parameters.TokenEndpointAuthSigningAlgValuesSupported),
            Strings(document, ConfigurationResponse.Parameters.IntrospectionEndpointAuthSigningAlgValuesSupported));
    }

    private static async Task<JsonObject> FetchDiscoveryJsonAsync(HttpClient client)
    {
        var response = await client.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        return await ReadJsonAsync(response);
    }

    private static string[] Strings(JsonObject document, string member)
    {
        Assert.True(document.ContainsKey(member), $"Discovery does not publish {member}.");
        return document[member]!.AsArray().Select(value => value!.GetValue<string>()).ToArray();
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        var body = await ReadJsonAsync(response);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }
}
