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
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof that a host granting new clients offline access without <c>prompt=consent</c>
/// (<see cref="NewClientOptions.OfflineAccess"/>) gives a client registering itself a refresh token from an
/// authorization request that does not ask for consent, both an OpenID Connect one and a plain OAuth 2.0 one, while a
/// client asking for less at registration is held to what it asked for.
/// </summary>
/// <remarks>
/// The host's default, which keeps such a client to <c>prompt=consent</c>, is proven by
/// <see cref="OfflineAccessTests"/>.
/// </remarks>
public class NewClientOfflineAccessTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task AClientRegisteringWithoutTheMember_IsRegisteredWithTheHostsGrant()
    {
        using var host = GrantingHost();
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);

        var registered = await RegisterClientAsync(client, discovery, PublicClient());

        Assert.Equal(OfflineAccess.Allowed, OfflineAccessOf(registered));
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 11 waives prompt=consent where "other conditions for processing the request
    /// permitting offline access" are in place, and the host's grant is that condition for the client.
    /// </summary>
    [Fact]
    public async Task AnOpenIdRequestForOfflineAccess_WithoutConsentPrompt_IsIssuedARefreshToken()
    {
        using var host = GrantingHost();
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = ClientIdOf(await RegisterClientAsync(client, discovery, PublicClient()));

        var tokens = await TokensAsync(client, discovery, clientId, $"{Scopes.OpenId} {Scopes.OfflineAccess}");

        Assert.NotNull(tokens[TokenResponse.Parameters.RefreshToken]);
    }

    /// <summary>
    /// A request without openid is a plain OAuth 2.0 one, where issuing a refresh token is the authorization server's
    /// discretion (RFC 6749 section 1.5), and the host's grant decides it the same way.
    /// </summary>
    [Fact]
    public async Task APlainOAuthRequestForOfflineAccess_WithoutConsentPrompt_IsIssuedARefreshToken()
    {
        using var host = GrantingHost();
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = ClientIdOf(await RegisterClientAsync(client, discovery, PublicClient()));

        var tokens = await TokensAsync(client, discovery, clientId, Scopes.OfflineAccess);

        Assert.NotNull(tokens[TokenResponse.Parameters.AccessToken]);
        Assert.NotNull(tokens[TokenResponse.Parameters.RefreshToken]);
    }

    /// <summary>
    /// A client asking for offline access with prompt=consent is registered with it under a host granting more, and its
    /// request without prompt=consent has offline_access ignored, as with the host's default.
    /// </summary>
    [Fact]
    public async Task AClientAskingForLess_IsHeldToWhatItAskedFor()
    {
        using var host = GrantingHost();
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var body = PublicClient();
        body[RequestMembers.OfflineAccess] = JsonSerializer.SerializeToNode(OfflineAccess.ConsentRequired);

        var registered = await RegisterClientAsync(client, discovery, body);
        Assert.Equal(OfflineAccess.ConsentRequired, OfflineAccessOf(registered));

        var tokens = await TokensAsync(
            client, discovery, ClientIdOf(registered), $"{Scopes.OpenId} {Scopes.OfflineAccess}");

        Assert.NotNull(tokens[TokenResponse.Parameters.AccessToken]);
        Assert.Null(tokens[TokenResponse.Parameters.RefreshToken]);
    }

    /// <summary>
    /// A host granting new clients no offline access refuses a client asking for offline access with prompt=consent.
    /// </summary>
    [Fact]
    public async Task AClientAskingForMoreThanTheHostGrants_IsRefused()
    {
        using var host = HostGranting(OfflineAccess.Disabled);
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var body = PublicClient();
        body[RequestMembers.OfflineAccess] = JsonSerializer.SerializeToNode(OfflineAccess.ConsentRequired);

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint, body, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<JsonObject>(TestContext.Current.CancellationToken);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error?[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// An RFC 7592 update builds the client anew, so one omitting the member takes the host's grant again.
    /// </summary>
    [Fact]
    public async Task AnUpdateWithoutTheMember_KeepsTheHostsGrant()
    {
        using var host = GrantingHost();
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, PublicClient());

        var body = PublicClient();
        body[RequestMembers.ClientId] = ClientIdOf(registered);
        using var update = new HttpRequestMessage(
            HttpMethod.Put,
            new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>(), UriKind.RelativeOrAbsolute));
        update.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        update.Content = JsonContent.Create(body);
        var response = await client.SendAsync(update, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var updated = await response.Content.ReadFromJsonAsync<JsonObject>(TestContext.Current.CancellationToken);
        Assert.Equal(OfflineAccess.Allowed, OfflineAccessOf(updated!));
    }

    /// <summary>
    /// A value the enumeration does not define, which configuration binds from a number, stops the host starting
    /// instead of failing every registration after it starts.
    /// </summary>
    [Fact]
    public void AnUndefinedOfflineAccessForNewClients_StopsTheHostStarting()
    {
        using var host = HostGranting((OfflineAccess)7);

        var refusal = Assert.ThrowsAny<Exception>(() => host.Server);

        Assert.Contains(Chain(refusal), exception => exception is OptionsValidationException
        {
            OptionsType: var type,
        } && type == typeof(OidcOptions));
    }

    private static IEnumerable<Exception> Chain(Exception exception)
    {
        for (var current = exception; current != null; current = current.InnerException)
        {
            yield return current;
            if (current is AggregateException aggregate)
                foreach (var inner in aggregate.InnerExceptions)
                    yield return inner;
        }
    }

    private WebApplicationFactory<Program> GrantingHost() => HostGranting(OfflineAccess.Allowed);

    private WebApplicationFactory<Program> HostGranting(OfflineAccess offlineAccess)
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<OidcOptions>(options => options.NewClientOptions = options.NewClientOptions with
            {
                OfflineAccess = offlineAccess,
            })));

    private static HttpClient ClientOf(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    /// <summary>
    /// The tokens an authorization code request for <paramref name="scope"/>, without prompt=consent, is exchanged for.
    /// </summary>
    private static async Task<JsonObject> TokensAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, string scope)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var parameters = CodeFlowParameters(clientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = scope;
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, parameters);

        return await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = clientId,
        });
    }

    private static JsonObject PublicClient() => new()
    {
        [RequestMembers.ClientName] = "offline access for new clients",
        [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken),
        [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
        [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.None,
    };

    private static string ClientIdOf(JsonObject registered)
        => registered[ResponseMembers.ClientId]!.GetValue<string>();

    private static OfflineAccess OfflineAccessOf(JsonObject registered)
        => registered[RequestMembers.OfflineAccess].Deserialize<OfflineAccess>();
}
