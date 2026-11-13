// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// Strict request object processing (RFC 9101 section 6.3) uses only the parameters inside the object. A client
/// registered with require_signed_request_object passes its parameters that way, so the signed object it sends is
/// accepted at the pushed authorization endpoint and at the authorization endpoint alike.
/// </remarks>
public partial class JarRichAuthorizationRequestsTests
{
    [Fact]
    public async Task StrictProcessing_PushedSignedRequestObject_IsAcceptedAndAuthorizes()
    {
        await using var host = CreateStrictHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var signing = await RegisterSigningClientAsync(client, discovery);

        var pushed = await PushAuthorizationRequestAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = signing.ClientId,
            [ClientRequest.Parameters.ClientSecret] = signing.ClientSecret,
            [AuthorizationRequest.Parameters.Request] = await SignRequestObjectAsync(discovery, signing),
        });
        var requestUri = pushed[PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = signing.ClientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });

        Assert.False(string.IsNullOrEmpty(code));
    }

    [Fact]
    public async Task StrictProcessing_SignedRequestObjectByValue_Authorizes()
    {
        await using var host = CreateStrictHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var signing = await RegisterSigningClientAsync(client, discovery);

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = signing.ClientId,
            [AuthorizationRequest.Parameters.Request] = await SignRequestObjectAsync(discovery, signing),
        });

        Assert.False(string.IsNullOrEmpty(code));
    }

    /// <summary>
    /// The same client pushing plain parameters is still refused, so the acceptance above is the signed object's.
    /// </summary>
    [Fact]
    public async Task StrictProcessing_PushedPlainParameters_AreRefused()
    {
        await using var host = CreateStrictHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var signing = await RegisterSigningClientAsync(client, discovery);
        var (_, challenge) = GeneratePkcePair();

        var form = CodeFlowParameters(signing.ClientId, challenge);
        form[ClientRequest.Parameters.ClientSecret] = signing.ClientSecret;
        var response = await FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidRequest, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    private sealed record SigningClient(string ClientId, string ClientSecret, RsaJsonWebKey Key);

    /// <summary>
    /// Builds an isolated host processing request objects strictly, leaving the shared default host untouched.
    /// </summary>
    private WebApplicationFactory<Program> CreateStrictHost()
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.IgnoreParametersOutsideRequestObject = true))));

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    /// <summary>
    /// Registers a client that must sign its request objects, with the public half of a fresh key as its jwks.
    /// </summary>
    private static async Task<SigningClient> RegisterSigningClientAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.Jwks] = JsonSerializer.SerializeToNode(PublicJwksFor(key)),
            [RegistrationMembers.RequireSignedRequestObject] = true,
        });

        return new SigningClient(
            registered[ClientRegistrationResponse.Parameters.ClientId]!.GetValue<string>(),
            registered[ClientRegistrationResponse.Parameters.ClientSecret]!.GetValue<string>(),
            key);
    }

    /// <summary>
    /// A request object carrying a whole code flow request, signed with the client's key.
    /// </summary>
    private static async Task<string> SignRequestObjectAsync(DiscoveryDocument discovery, SigningClient signing)
    {
        var (_, challenge) = GeneratePkcePair();
        var now = TimeProvider.System.GetUtcNow();
        var requestJwt = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, KeyId = signing.Key.KeyId },
            Payload =
            {
                Issuer = signing.ClientId,
                Audiences = [discovery.Issuer.OriginalString],
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
        foreach (var (name, value) in CodeFlowParameters(signing.ClientId, challenge))
            requestJwt.Payload.Json[name] = value;

        return await JwtServices.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(requestJwt, signing.Key);
    }
}
