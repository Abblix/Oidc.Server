// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 10070 section 4, case B, at every endpoint that authenticates a client besides the token and pushed
/// authorization request endpoints: the server "MUST reject any JWT that does not contain its issuer identifier as its
/// sole audience value". A private_key_jwt client is refused as one that cannot authenticate when its assertion names
/// the token endpoint URL alone or the issuer beside another recipient, and served when it names the issuer alone.
/// </summary>
public class PrivateKeyJwtAudienceTests(TestFactory factory) : TestBase(factory)
{
    private const string Introspection = "introspection";
    private const string Revocation = "revocation";
    private const string BackChannelAuthentication = "backchannel_authentication";
    private const string DeviceAuthorization = "device_authorization";

    /// <summary>
    /// Each refusal is paired with the same request from the same client naming the issuer alone, which the endpoint
    /// serves, so the refusals are the audience's and not the client's, the endpoint's or the request's.
    /// </summary>
    [Theory]
    [InlineData(Introspection)]
    [InlineData(Revocation)]
    [InlineData(BackChannelAuthentication)]
    [InlineData(DeviceAuthorization)]
    public async Task AnAssertionNotNamingTheIssuerAlone_IsRefusedAsInvalidClient(string endpointName)
    {
        // A host reaching the end-user, so a backchannel authentication its client starts is served
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Replace(ServiceDescriptor
                    .Scoped<IUserDeviceAuthenticationHandler, ReachableUserDeviceHandler>())));
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(http);
        var clientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var clientId = await RegisterAsync(http, discovery, clientKey);
        var (endpoint, form) = RequestTo(endpointName, discovery);
        var issuer = discovery.Issuer.OriginalString;

        foreach (var audiences in new[]
                 {
                     new[] { discovery.TokenEndpoint.OriginalString },
                     new[] { endpoint.OriginalString },
                     new[] { issuer, "https://another-server.example.com" },
                 })
        {
            using var refused = await PostAsync(host, http, endpoint, form, clientId, clientKey, audiences);

            var body = await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.False(refused.IsSuccessStatusCode, $"accepted [{string.Join(", ", audiences)}]: {body}");
            Assert.Equal(
                ErrorCodes.InvalidClient,
                JsonNode.Parse(body)![ErrorResponse.Parameters.Error]?.GetValue<string>());
        }

        using var served = await PostAsync(host, http, endpoint, form, clientId, clientKey, [issuer]);
        var servedBody = await served.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(served.IsSuccessStatusCode, $"{(int)served.StatusCode}: {servedBody}");
    }

    /// <summary>
    /// The endpoint <paramref name="endpointName"/> names and the parameters of a request it serves.
    /// </summary>
    private static (Uri Endpoint, Dictionary<string, string> Form) RequestTo(
        string endpointName, DiscoveryDocument discovery) => endpointName switch
    {
        Introspection => (discovery.IntrospectionEndpoint!,
            new Dictionary<string, string> { [IntrospectionRequest.Parameters.Token] = "any-token" }),
        Revocation => (discovery.RevocationEndpoint!,
            new Dictionary<string, string> { [RevocationRequest.Parameters.Token] = "any-token" }),
        BackChannelAuthentication => (discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = ReachableUserDeviceHandler.Subject,
            }),
        DeviceAuthorization => (discovery.DeviceAuthorizationEndpoint!,
            new Dictionary<string, string> { [DeviceAuthorizationRequest.Parameters.Scope] = Scopes.OpenId }),
        _ => throw new ArgumentOutOfRangeException(nameof(endpointName), endpointName, null),
    };

    /// <summary>
    /// Registers a private_key_jwt client verified with the public half of <paramref name="clientKey"/>, allowed
    /// every grant the endpoints under test serve, and held to the audience every new client is: the issuer alone.
    /// </summary>
    private static async Task<string> RegisterAsync(HttpClient http, DiscoveryDocument discovery, RsaJsonWebKey clientKey)
    {
        var registered = await RegisterClientAsync(http, discovery, new JsonObject
        {
            [RegistrationMembers.ClientName] = $"private-key-jwt-{Guid.NewGuid():N}",
            [RegistrationMembers.ResponseTypes] = new JsonArray(),
            [RegistrationMembers.GrantTypes] = new JsonArray(
                GrantTypes.ClientCredentials, GrantTypes.Ciba, GrantTypes.DeviceAuthorization),
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt,
            [RegistrationMembers.TokenEndpointAuthSigningAlg] = SigningAlgorithms.RS256,
            [RegistrationMembers.Jwks] = JsonSerializer.SerializeToNode(
                new JsonWebKeySet([clientKey.Sanitize(includePrivateKeys: false)])),
            [RegistrationMembers.BackChannelTokenDeliveryMode] = BackchannelTokenDeliveryModes.Poll,
        });

        return registered[ClientRegistrationResponse.Parameters.ClientId]!.GetValue<string>();
    }

    /// <summary>
    /// Posts <paramref name="form"/> beside a private_key_jwt assertion of <paramref name="clientId"/> with a fresh jti,
    /// naming <paramref name="audiences"/>.
    /// </summary>
    private static async Task<HttpResponseMessage> PostAsync(
        WebApplicationFactory<Program> host,
        HttpClient http,
        Uri endpoint,
        Dictionary<string, string> form,
        string clientId,
        RsaJsonWebKey clientKey,
        string[] audiences)
    {
        var now = TimeProvider.System.GetUtcNow();
        var assertion = await host.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.RS256, KeyId = clientKey.KeyId },
                Payload =
                {
                    JwtId = Guid.NewGuid().ToString("N"),
                    Issuer = clientId,
                    Subject = clientId,
                    Audiences = audiences,
                    IssuedAt = now,
                    NotBefore = now,
                    ExpiresAt = now.AddMinutes(1),
                },
            },
            clientKey);

        var request = new Dictionary<string, string>(form)
        {
            [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
            [ClientRequest.Parameters.ClientAssertion] = assertion,
        };
        return await FormPostHelpers.PostFormAsync(http, endpoint, request);
    }
}
