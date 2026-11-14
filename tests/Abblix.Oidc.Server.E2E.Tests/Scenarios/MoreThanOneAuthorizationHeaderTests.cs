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
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A request carrying the Authorization header field more than once. RFC 9110 section 11.6.2 defines the field as
/// <c>Authorization = credentials</c>, not a list, so section 5.3 forbids a sender to generate it twice and a
/// recipient cannot recombine the lines into one value. RFC 6750 section 3.1 names a protected-resource request that
/// "uses more than one method for including an access token" an invalid_request answered with 400 (RFC 9449 Figure
/// 19 shows the Bearer and DPoP pair), and RFC 6749 section 5.2 names a request to the authorization server that
/// "includes multiple credentials, utilizes more than one mechanism for authenticating the client" the same.
/// Each request sends the field as separate lines, never as one joined value.
/// </summary>
public class MoreThanOneAuthorizationHeaderTests(TestFactory factory) : TestBase(factory)
{
    private static readonly string BasicCredentials = Convert.ToBase64String(
        System.Text.Encoding.ASCII.GetBytes(
            $"{TestConstants.ClientSecretBasicClientId}:{TestConstants.ConfidentialClientSecret}"));

    private static void AddAuthorizationLines(HttpRequestMessage request, params string[] lines)
    {
        Assert.True(request.Headers.TryAddWithoutValidation(HttpRequestHeaders.Authorization, lines));
        Assert.Equal(lines, request.Headers.NonValidated[HttpRequestHeaders.Authorization]);
    }

    private static async Task AssertInvalidRequestAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {raw}");
        Assert.Equal(ErrorCodes.InvalidRequest, JsonNode.Parse(raw)![ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    private async Task<(HttpClient Client, Uri Endpoint, string AccessToken)> ObtainAccessTokenAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        return (client, discovery.UserInfoEndpoint!, tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
    }

    /// <summary>
    /// RFC 9449 Figure 19: the same token under the Bearer and the DPoP scheme, and a token repeated under one scheme.
    /// </summary>
    [Theory]
    [InlineData(TokenTypes.Bearer, TokenTypes.DPoP)]
    [InlineData(TokenTypes.Bearer, TokenTypes.Bearer)]
    public async Task UserInfo_with_two_authorization_lines_is_an_invalid_request(string first, string second)
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        AddAuthorizationLines(request, $"{first} {accessToken}", $"{second} {accessToken}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertInvalidRequestAsync(response);
    }

    /// <summary>
    /// Two lines beside a token in the body are still more than one method, and the body token is not read instead.
    /// </summary>
    [Fact]
    public async Task UserInfo_with_two_authorization_lines_and_a_body_token_is_an_invalid_request()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(
                new Dictionary<string, string> { [UserInfoRequest.Parameters.AccessToken] = accessToken }),
        };
        AddAuthorizationLines(request, $"{TokenTypes.Bearer} {accessToken}", $"{TokenTypes.Bearer} {accessToken}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertInvalidRequestAsync(response);
    }

    [Fact]
    public async Task UserInfo_with_one_authorization_line_is_answered()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        AddAuthorizationLines(request, $"{TokenTypes.Bearer} {accessToken}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// The two credentials joined into one line, as RFC 9110 section 5.3 lets an intermediary combine field lines, are
    /// one value that is not credentials at all, so the request is answered 401 as carrying none. This is the
    /// control that tells the two-line rows above apart from a host that joined the lines before the library saw them.
    /// </summary>
    [Fact]
    public async Task UserInfo_with_two_credentials_joined_into_one_line_is_read_as_no_credentials()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        AddAuthorizationLines(request, $"{TokenTypes.Bearer} {accessToken}, {TokenTypes.DPoP} {accessToken}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static FormUrlEncodedContent ClientCredentialsGrant(bool withSecretInBody = false)
    {
        var form = new Dictionary<string, string> { [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials };
        if (withSecretInBody)
        {
            form[ClientRequest.Parameters.ClientId] = TestConstants.ClientSecretBasicClientId;
            form[ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret;
        }

        return new FormUrlEncodedContent(form);
    }

    [Fact]
    public async Task Token_endpoint_with_two_basic_lines_is_an_invalid_request()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint) { Content = ClientCredentialsGrant() };
        AddAuthorizationLines(request, $"{TokenTypes.Basic} {BasicCredentials}", $"{TokenTypes.Basic} {BasicCredentials}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertInvalidRequestAsync(response);
    }

    [Fact]
    public async Task Token_endpoint_with_one_basic_line_is_answered()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint) { Content = ClientCredentialsGrant() };
        AddAuthorizationLines(request, $"{TokenTypes.Basic} {BasicCredentials}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// One Authorization line beside the same credentials in the body is still served, as it was before the lines were
    /// counted. RFC 6749 section 2.3 says "The client MUST NOT use more than one authentication method in each
    /// request", and the server does not refuse this pair today; the row pins that answer, so changing it is a decision
    /// made visibly rather than a side effect of counting lines.
    /// </summary>
    [Fact]
    public async Task Token_endpoint_with_one_basic_line_and_a_body_secret_is_answered_as_before()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = ClientCredentialsGrant(withSecretInBody: true),
        };
        AddAuthorizationLines(request, $"{TokenTypes.Basic} {BasicCredentials}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// Every other endpoint authenticating the client as the token endpoint does (RFC 7662 section 2.1, RFC 7009
    /// section 2.1, RFC 9126 section 2.1, RFC 8628 section 3.1, OpenID CIBA Core section 7.1) answers the field sent
    /// twice the same way.
    /// </summary>
    [Theory]
    [InlineData(nameof(DiscoveryDocument.IntrospectionEndpoint))]
    [InlineData(nameof(DiscoveryDocument.RevocationEndpoint))]
    [InlineData(nameof(DiscoveryDocument.PushedAuthorizationRequestEndpoint))]
    [InlineData(nameof(DiscoveryDocument.DeviceAuthorizationEndpoint))]
    [InlineData(nameof(DiscoveryDocument.BackChannelAuthenticationEndpoint))]
    public async Task Client_authenticating_endpoint_with_two_basic_lines_is_an_invalid_request(string endpointName)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var endpoint = (Uri?)typeof(DiscoveryDocument).GetProperty(endpointName)!.GetValue(discovery);
        Assert.NotNull(endpoint);

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = "any",
                [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            }),
        };
        AddAuthorizationLines(request, $"{TokenTypes.Basic} {BasicCredentials}", $"{TokenTypes.Basic} {BasicCredentials}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertInvalidRequestAsync(response);
    }

    private async Task<(HttpClient Client, Uri ConfigurationUri, string RegistrationAccessToken)> RegisterAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
        });

        return (
            client,
            new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>(), UriKind.RelativeOrAbsolute),
            registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
    }

    /// <summary>
    /// RFC 7592 section 2.1: a registration access token "not valid" is answered "as described in the OAuth Bearer
    /// Token Usage specification", whose section 3.1 makes more than one method an invalid_request.
    /// </summary>
    [Fact]
    public async Task Client_configuration_endpoint_with_two_bearer_lines_is_an_invalid_request()
    {
        var (client, configurationUri, token) = await RegisterAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, configurationUri);
        AddAuthorizationLines(request, $"{TokenTypes.Bearer} {token}", $"{TokenTypes.Bearer} {token}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertInvalidRequestAsync(response);
    }

    [Fact]
    public async Task Client_configuration_endpoint_with_one_bearer_line_is_answered()
    {
        var (client, configurationUri, token) = await RegisterAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, configurationUri);
        AddAuthorizationLines(request, $"{TokenTypes.Bearer} {token}");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private async Task<HttpResponseMessage> RegisterWithInitialAccessTokenRequiredAsync(params string[] lines)
    {
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.RequireInitialAccessToken = true))));

        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.RegistrationEndpoint)
        {
            Content = JsonContent.Create(new JsonObject
            {
                [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            }),
        };
        AddAuthorizationLines(request, lines);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        await response.Content.LoadIntoBufferAsync(TestContext.Current.CancellationToken);
        return response;
    }

    /// <summary>
    /// RFC 7591 section 3.2.2 answers an initial access token error "appropriate to the OAuth 2.0 token type", and
    /// RFC 6750 section 3.1 makes more than one method an invalid_request. The lines are refused before either token
    /// is read, so neither has to be valid.
    /// </summary>
    [Fact]
    public async Task Registration_with_two_bearer_lines_is_an_invalid_request()
    {
        var response = await RegisterWithInitialAccessTokenRequiredAsync(
            $"{TokenTypes.Bearer} first", $"{TokenTypes.Bearer} second");

        await AssertInvalidRequestAsync(response);
    }

    /// <summary>
    /// One line carrying a token that is not valid is judged as the token it carries.
    /// </summary>
    [Fact]
    public async Task Registration_with_one_bearer_line_is_judged_by_its_token()
    {
        var response = await RegisterWithInitialAccessTokenRequiredAsync($"{TokenTypes.Bearer} first");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
