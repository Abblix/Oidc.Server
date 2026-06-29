// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// End-to-end coverage of the Minimal API adapter's core form-encoded POST endpoints, driven through a real
/// ASP.NET Core request pipeline. Every request is bound by a source-generated <c>BindAsync</c> (TokenRequest,
/// ClientRequest, AuthorizationRequest via PAR, IntrospectionRequest, RevocationRequest), so a green run confirms
/// the generated models read <c>application/x-www-form-urlencoded</c> bodies identically to the hand-written
/// models they replaced.
/// </summary>
public sealed class FormEncodedAdapterTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
    });

    [Fact]
    public async Task Discovery_and_jwks_are_served()
    {
        var client = CreateClient();

        var discovery = await client.FetchDiscoveryAsync();
        Assert.Equal(TestConstants.Issuer, discovery[ConfigurationResponse.Parameters.Issuer]!.GetValue<string>());

        var jwks = await client.GetJsonAsync(discovery[ConfigurationResponse.Parameters.JwksUri]!.GetValue<string>());
        Assert.NotEmpty(jwks["keys"]!.AsArray());
    }

    [Fact]
    public async Task Client_credentials_token_request_issues_access_token()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        // client_credentials + ClientSecretPost + an RFC 8707 resource indicator. The resource parameter exercises
        // the generated TokenRequest's Uri[] ParseUris binding; grant_type / client_id / client_secret exercise the
        // plain-string bindings of TokenRequest and ClientRequest.
        var token = await client.PostFormJsonAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.TokenEndpoint),
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [ClientRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
                [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
            });

        Assert.NotNull(token[ResponseParameters.AccessToken]);
        Assert.Equal(TokenTypes.Bearer, token[ResponseParameters.TokenType]!.GetValue<string>());
    }

    [Fact]
    public async Task Token_request_with_wrong_secret_is_rejected_as_invalid_client()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        var response = await client.PostFormAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.TokenEndpoint),
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [ClientRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
                [ClientRequest.Parameters.ClientSecret] = "wrong-secret",
            });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidClient, body[ResponseParameters.Error]!.GetValue<string>());
    }

    [Fact]
    public async Task Authorization_code_token_introspects_active_then_revokes_to_inactive()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        // A stored (stateful) access token via the auth-code path, so the introspection endpoint can look it up —
        // unlike the stateless client_credentials JWT. The PAR step also exercises the generated AuthorizationRequest
        // binding from a form POST.
        var accessToken = (await client.AuthCodeTokensViaParAsync(discovery, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret))
            [ResponseParameters.AccessToken]!.GetValue<string>();

        var before = await IntrospectAsync(client, discovery, accessToken);
        Assert.True(before[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());

        var revoked = await client.PostFormAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.RevocationEndpoint),
            new Dictionary<string, string>
            {
                [RevocationRequest.Parameters.Token] = accessToken,
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            });
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);

        var after = await IntrospectAsync(client, discovery, accessToken);
        Assert.False(after[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    private static Task<JsonObject> IntrospectAsync(HttpClient client, JsonObject discovery, string token)
        => client.PostFormJsonAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.IntrospectionEndpoint),
            new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = token,
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            });
}
