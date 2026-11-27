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
/// A client registering itself cannot state those conditions, so under the host's default for new clients a
/// dynamically registered client is the one the host has not configured; a host granting more is proven by
/// <see cref="NewClientOfflineAccessTests"/>.
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

        /// <summary>
        /// The scopes the end user was last asked to consent to.
        /// </summary>
        public string[] Asked { get; private set; } = [];

        public Task<UserConsents> GetUserConsentsAsync(
            Abblix.Oidc.Server.Features.MultiTenancy.TenantDefinition tenant, ValidAuthorizationRequest request, AuthSession authSession)
        {
            Asked = [.. request.Scope.Select(scope => scope.Scope)];
            return Task.FromResult(new UserConsents
            {
                Granted = new ConsentDefinition(request.Scope, request.Resources),
                GivenAt = _givenAt,
            });
        }

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

        Assert.NotNull(tokens[TokenResponse.Parameters.AccessToken]);
        Assert.Null(tokens[TokenResponse.Parameters.RefreshToken]);
    }

    /// <summary>
    /// The request asking for consent goes to the consent page, comes back with the request it left with once the
    /// end user gives consent, and its code is exchanged for a refresh token.
    /// </summary>
    [Fact]
    public async Task OfflineAccessWithConsentPrompt_ComesBackFromTheConsentPage_AndARefreshTokenIsIssued()
    {
        var consents = new ConsentGivenOnThePage();

        var tokens = await TokensWithConsentAsync(PublicClient(), consents);

        Assert.Contains(Scopes.OfflineAccess, consents.Asked);
        Assert.NotNull(tokens[TokenResponse.Parameters.RefreshToken]);
    }

    /// <summary>
    /// A client registered without the refresh token grant - grant_types omitted, which RFC 7591 section 2 reads as
    /// authorization_code alone, or stated without it - is issued no refresh token even with consent given: the token
    /// endpoint would refuse it with unauthorized_client the moment the client presented it. Its offline_access is
    /// ignored at the authorization step, so the end user is not asked to consent to it.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AClientRegisteredWithoutTheRefreshGrant_IsIssuedNoRefreshToken(bool statesGrantTypes)
    {
        var registration = PublicClient();
        if (statesGrantTypes)
            registration[RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode);
        else
            registration.Remove(RequestMembers.GrantTypes);

        var consents = new ConsentGivenOnThePage();

        var tokens = await TokensWithConsentAsync(registration, consents);

        Assert.Contains(Scopes.OpenId, consents.Asked);
        Assert.DoesNotContain(Scopes.OfflineAccess, consents.Asked);
        Assert.NotNull(tokens[TokenResponse.Parameters.AccessToken]);
        Assert.Null(tokens[TokenResponse.Parameters.RefreshToken]);
    }

    /// <summary>
    /// The tokens a client registered with <paramref name="registration"/> is issued for an OpenID request for offline
    /// access with prompt=consent, once the end user gives consent on the consent page.
    /// </summary>
    private async Task<JsonObject> TokensWithConsentAsync(JsonObject registration, ConsentGivenOnThePage consents)
    {
        using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(
            services => services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider>(consents))));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, registration);
        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();
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
        var code = QueryValue(back, ResponseParameters.Code);
        Assert.NotNull(code);

        return await ExchangeAsync(client, discovery, clientId, code, verifier);
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
    public Task AClientRegisteringItself_AskingForOfflineAccessWithoutConsentPrompt_IsRefused()
        => AssertRegistrationRefusedAsync(JsonSerializer.SerializeToNode(OfflineAccess.Allowed));

    /// <summary>
    /// A number, or a list of names, reads into a value the enumeration does not name, and the registration is
    /// refused with invalid_client_metadata rather than failing on the server.
    /// </summary>
    [Theory]
    [InlineData("7")]
    [InlineData("\"7\"")]
    [InlineData("\"consent_required,allowed\"")]
    public Task AClientRegisteringItself_WithAnUnnamedOfflineAccess_IsRefused(string value)
        => AssertRegistrationRefusedAsync(JsonNode.Parse(value));

    private async Task AssertRegistrationRefusedAsync(JsonNode? offlineAccess)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var body = PublicClient();
        body[RequestMembers.OfflineAccess] = offlineAccess;

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint, body, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<JsonObject>(TestContext.Current.CancellationToken);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error?[ErrorResponse.Parameters.Error]?.GetValue<string>());
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
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = clientId,
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
