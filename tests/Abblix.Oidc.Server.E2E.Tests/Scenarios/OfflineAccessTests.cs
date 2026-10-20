// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of OpenID Connect Core 1.0, section 11, through the real authorization and token endpoints: a
/// request for offline access gets a refresh token when it asks for consent with <c>prompt=consent</c> and the end
/// user gives it on the consent page, and has its <c>offline_access</c> ignored, with no refresh token, when it does
/// not ask and the host has not configured the client to receive offline access without it.
/// </summary>
/// <remarks>
/// A client registering itself cannot state those conditions, so a dynamically registered client is the one the
/// host has not configured.
/// </remarks>
public class OfflineAccessTests(TestFactory factory) : TestBase(factory)
{
    private const string ConsentPath = "/consent";

    /// <summary>
    /// The consent the host keeps: everything the request asks, given once the end user answers the consent page.
    /// </summary>
    private sealed class ConsentGivenOnThePage : IUserConsentsProvider
    {
        private DateTimeOffset? _givenAt;

        public Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
            => Task.FromResult(new UserConsents
            {
                Granted = new ConsentDefinition(request.Scope, request.Resources),
                GivenAt = _givenAt,
            });

        public void Give() => _givenAt = TimeProvider.System.GetUtcNow();
    }

    [Fact]
    public async Task OfflineAccessWithoutConsentPrompt_IsIgnored_AndNoRefreshTokenIsIssued()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = await RegisterPublicClientAsync(client, discovery);
        var (verifier, challenge) = GeneratePkcePair();

        var parameters = CodeFlowParameters(clientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}";
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, parameters);

        var tokens = await ExchangeAsync(client, discovery, clientId, code, verifier);

        Assert.NotNull(tokens[UserInfoRequest.Parameters.AccessToken]);
        Assert.Null(tokens[TokenRequest.Parameters.RefreshToken]);
    }

    /// <summary>
    /// The request asking for consent goes to the consent page, comes back with the request it left with once the
    /// end user gives consent, and its code is exchanged for a refresh token.
    /// </summary>
    [Fact]
    public async Task OfflineAccessWithConsentPrompt_ComesBackFromTheConsentPage_AndARefreshTokenIsIssued()
    {
        var consents = new ConsentGivenOnThePage();
        using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(
            services => services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider>(consents))));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = await RegisterPublicClientAsync(client, discovery);
        var (verifier, challenge) = GeneratePkcePair();

        var parameters = CodeFlowParameters(clientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}";
        parameters[AuthorizationRequest.Parameters.Prompt] = Prompts.Consent;
        var page = await RedirectOf(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters));
        Assert.Equal(ConsentPath, page.AbsolutePath);

        consents.Give();
        var back = await RedirectOf(client, QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [AuthorizationRequest.Parameters.RequestUri] =
                    QueryValue(page, AuthorizationRequest.Parameters.RequestUri)!,
            }));
        var code = QueryValue(back, TokenRequest.Parameters.Code);
        Assert.NotNull(code);

        var tokens = await ExchangeAsync(client, discovery, clientId, code, verifier);

        Assert.NotNull(tokens[TokenRequest.Parameters.RefreshToken]);
    }

    /// <summary>
    /// A client registering itself without saying what offline access it asks for is registered with offline access
    /// that requires prompt=consent, and its registration says so.
    /// </summary>
    [Fact]
    public async Task AClientRegisteringItself_ReceivesOfflineAccessWithConsentPrompt_WhenItDoesNotSay()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var registered = await RegisterClientAsync(client, discovery, PublicClient());

        Assert.Equal(
            OfflineAccess.ConsentRequired,
            registered[RequestMembers.OfflineAccess].Deserialize<OfflineAccess>());
    }

    /// <summary>
    /// Waiving prompt=consent is the host's statement about a client, so a client asking for it at registration is
    /// refused with invalid_client_metadata.
    /// </summary>
    [Fact]
    public async Task AClientRegisteringItself_AskingForOfflineAccessWithoutConsentPrompt_IsRefused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var body = PublicClient();
        body[RequestMembers.OfflineAccess] = JsonSerializer.SerializeToNode(OfflineAccess.Allowed);

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint, body, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<JsonObject>(TestContext.Current.CancellationToken);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error?[ResponseParameters.Error]?.GetValue<string>());
    }

    private static JsonObject PublicClient() => new()
    {
        [RequestMembers.ClientName] = "offline access",
        [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken),
        [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
        [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.None,
    };

    private static async Task<string> RegisterPublicClientAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, PublicClient());
        return registered[ResponseMembers.ClientId]!.GetValue<string>();
    }

    private static Task<JsonObject> ExchangeAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, string code, string verifier)
        => ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
        });

    /// <summary>
    /// Where the endpoint at <paramref name="uri"/> redirects the browser, resolved against the test server, so a
    /// page on the server and the client's redirect URI read the same way.
    /// </summary>
    private static async Task<Uri> RedirectOf(HttpClient client, Uri uri)
    {
        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther, $"{response.StatusCode}");
        Assert.NotNull(response.Headers.Location);
        return new Uri(TestServerAddress.BaseAddress, response.Headers.Location);
    }

    private static string? QueryValue(Uri location, string name)
        => System.Web.HttpUtility.ParseQueryString(location.Query)[name];
}
