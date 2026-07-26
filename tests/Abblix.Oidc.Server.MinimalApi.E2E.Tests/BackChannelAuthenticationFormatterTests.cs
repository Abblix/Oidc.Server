// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Net.Http.Headers;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using ClientParameters = Abblix.Oidc.Server.Model.ClientRequest.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The CIBA result formatter, which had no coverage at all: the Minimal API host opts the endpoint in, and no
/// request ever reached it, so every one of its arms was unexercised.
/// </summary>
/// <remarks>
/// The three refusal arms differ in status and in what they carry, and only one of them is reachable without
/// an integrator-supplied device handler. A client that fails authentication is refused earlier, by the
/// validator, and gets the plain 400 - the 401 and 403 arms belong to a device handler that refuses a request
/// whose client already authenticated, which is why the tests below replace that handler rather than sending
/// bad credentials.
///
/// The 401 arm is the one worth driving carefully: RFC 9110 section 11.6.1 requires a challenge on a 401, and
/// per RFC 6749 section 5.2 its scheme has to match what the client attempted, so a client that sent Basic
/// credentials gets a Basic challenge and one that sent none gets Bearer. Getting that backwards sends a
/// client round a retry loop it cannot win.
/// </remarks>
public sealed class BackChannelAuthenticationFormatterTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private const string LoginHint = "someone@example.com";

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestFactory.BaseAddress,
        });

    private WebApplicationFactory<Program> HostRefusingWith(OidcError refusal)
        => factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Replace(ServiceDescriptor.Scoped<IUserDeviceAuthenticationHandler>(
                    _ => new RefusingUserDeviceHandler(refusal)))));

    /// <summary>
    /// A CIBA client has to be registered as one: the grant and a token delivery mode, and no redirect URI,
    /// because the flow never touches a browser. The default confidential client of the host declares none of
    /// that, so a request in its name is refused by validation long before the device handler is consulted.
    /// </summary>
    private static async Task<(string ClientId, string Secret)> RegisterCibaClientAsync(
        HttpClient client, JsonObject discovery, string authMethod = ClientAuthenticationMethods.ClientSecretPost)
    {
        var response = await client.PostAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.RegistrationEndpoint),
            JsonContent.Create(new JsonObject
            {
                [ClientRegistrationRequest.Parameters.ClientName] = $"ciba-{Guid.NewGuid():N}",
                [ClientRegistrationRequest.Parameters.ResponseTypes] = new JsonArray(),
                [ClientRegistrationRequest.Parameters.GrantTypes] = new JsonArray { GrantTypes.Ciba },
                [ClientRegistrationRequest.Parameters.TokenEndpointAuthMethod] = authMethod,
                [ClientRegistrationRequest.Parameters.BackChannelTokenDeliveryMode] =
                    BackchannelTokenDeliveryModes.Poll,
            }),
            TestContext.Current.CancellationToken);

        var body = await ReadJsonAsync(response);
        Assert.True(response.IsSuccessStatusCode, $"registering a CIBA client failed: {(int)response.StatusCode} {body}");

        var clientId = body[ClientParameters.ClientId];
        var secret = body[ClientParameters.ClientSecret];
        Assert.NotNull(clientId);
        Assert.NotNull(secret);

        return (clientId.GetValue<string>(), secret.GetValue<string>());
    }

    private static Dictionary<string, string> RequestFor((string ClientId, string Secret) ciba) => new()
    {
        [ClientParameters.ClientId] = ciba.ClientId,
        [ClientParameters.ClientSecret] = ciba.Secret,
        [CibaParameters.Scope] = Scopes.OpenId,
        [CibaParameters.LoginHint] = LoginHint,
    };

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var node = JsonNode.Parse(raw);
        Assert.NotNull(node);

        return node.AsObject();
    }

    [Fact]
    public async Task A_device_handler_refusing_the_client_answers_401_with_a_bearer_challenge()
    {
        await using var host = HostRefusingWith(
            new OidcError(ErrorCodes.UnauthorizedClient, "this client may not reach that user"));
        var client = CreateClientFor(host);
        var discovery = await client.FetchDiscoveryAsync();
        var endpoint = OidcFlows.Endpoint(
            discovery, ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        var response = await client.PostFormAsync(endpoint, RequestFor(ciba));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // The credentials went in the body, not the Authorization header, so the challenge names Bearer.
        var challenge = Assert.Single(response.Headers.GetValues(HeaderNames.WWWAuthenticate));
        Assert.StartsWith(TokenTypes.Bearer, challenge, StringComparison.Ordinal);
        Assert.Contains(TestConstants.Issuer, challenge, StringComparison.Ordinal);

        var body = await ReadJsonAsync(response);
        var error = body[ResponseParameters.Error];
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.AccessDenied, error.GetValue<string>());
    }

    /// <summary>
    /// The same refusal to a client that authenticated through the Authorization header: the challenge has to
    /// name the scheme that client used, or it is told to retry with one it never attempted.
    /// </summary>
    [Fact]
    public async Task The_challenge_names_the_scheme_the_client_actually_used()
    {
        await using var host = HostRefusingWith(
            new OidcError(ErrorCodes.UnauthorizedClient, "this client may not reach that user"));
        var client = CreateClientFor(host);
        var discovery = await client.FetchDiscoveryAsync();
        var endpoint = OidcFlows.Endpoint(
            discovery, ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint);
        // Registered for the header-based method, because a client is only allowed to authenticate the way it
        // registered: sending Basic credentials for a client_secret_post client is refused by the validator
        // long before the device handler is reached, and the challenge branch under test never runs.
        var ciba = await RegisterCibaClientAsync(
            client, discovery, ClientAuthenticationMethods.ClientSecretBasic);

        var credentials = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{ciba.ClientId}:{ciba.Secret}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(TokenTypes.Basic, credentials);

        var response = await client.PostFormAsync(endpoint, new Dictionary<string, string>
        {
            [CibaParameters.Scope] = Scopes.OpenId,
            [CibaParameters.LoginHint] = LoginHint,
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var challenge = Assert.Single(response.Headers.GetValues(HeaderNames.WWWAuthenticate));
        Assert.StartsWith(TokenTypes.Basic, challenge, StringComparison.Ordinal);
    }

    /// <summary>
    /// The user refusing is not the client being unauthorised: 403 says the request was understood and denied,
    /// and it carries no challenge because retrying with different credentials would not help.
    /// </summary>
    [Fact]
    public async Task A_device_handler_reporting_the_user_declined_answers_403_without_a_challenge()
    {
        await using var host = HostRefusingWith(
            new OidcError(ErrorCodes.AccessDenied, "the user declined on their device"));
        var client = CreateClientFor(host);
        var discovery = await client.FetchDiscoveryAsync();
        var endpoint = OidcFlows.Endpoint(
            discovery, ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        var response = await client.PostFormAsync(endpoint, RequestFor(ciba));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains(HeaderNames.WWWAuthenticate));

        var body = await ReadJsonAsync(response);
        var error = body[ResponseParameters.Error];
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.AccessDenied, error.GetValue<string>());
    }

    /// <summary>
    /// Everything else lands on the plain 400 arm, reached here without touching the device handler: a request
    /// that names nobody to reach never gets that far.
    /// </summary>
    [Fact]
    public async Task A_request_that_names_nobody_is_refused_with_400_and_no_challenge()
    {
        var client = CreateClientFor(factory);
        var discovery = await client.FetchDiscoveryAsync();
        var endpoint = OidcFlows.Endpoint(
            discovery, ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        var form = RequestFor(ciba);
        form.Remove(CibaParameters.LoginHint);

        var response = await client.PostFormAsync(endpoint, form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains(HeaderNames.WWWAuthenticate));

        var body = await ReadJsonAsync(response);
        Assert.False(string.IsNullOrEmpty(body[ResponseParameters.Error]?.GetValue<string>()));
    }

    /// <summary>
    /// Stands in for the integrator-supplied device interaction and refuses with the error the test needs, so
    /// the refusal arms of the formatter are reached the only way production reaches them.
    /// </summary>
    private sealed class RefusingUserDeviceHandler(OidcError refusal) : IUserDeviceAuthenticationHandler
    {
        public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
            ValidBackChannelAuthenticationRequest request)
            => Task.FromResult<Result<AuthSession, OidcError>>(refusal);
    }
}
