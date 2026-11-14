// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using System.Net.Http.Headers;
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
using Microsoft.AspNetCore.Http;
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
            [AuthorizationRequest.Parameters.Request] = await SignRequestObjectAsync(discovery, signing, GeneratePkcePair().Challenge),
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
            [AuthorizationRequest.Parameters.Request] = await SignRequestObjectAsync(discovery, signing, GeneratePkcePair().Challenge),
        });

        Assert.False(string.IsNullOrEmpty(code));
    }

    /// <summary>
    /// RFC 9449 section 10.1: a DPoP proof sent with the pushed request binds the code to its key. The request read
    /// back at the authorization endpoint keeps that binding, so a proof by another key is refused at the token
    /// endpoint.
    /// </summary>
    [Fact]
    public async Task StrictProcessing_PushedSignedRequestObjectWithDPoP_BindsTheCodeToTheKey()
    {
        await using var host = CreateStrictHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var signing = await RegisterSigningClientAsync(client, discovery);
        var (verifier, challenge) = GeneratePkcePair();
        using var pushKey = new DPoPProofGenerator();
        using var otherKey = new DPoPProofGenerator();

        var pushResponse = await FormPostHelpers.PostFormAsync(
            client,
            discovery.PushedAuthorizationRequestEndpoint!,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = signing.ClientId,
                [ClientRequest.Parameters.ClientSecret] = signing.ClientSecret,
                [AuthorizationRequest.Parameters.Request] = await SignRequestObjectAsync(discovery, signing, challenge),
            },
            pushKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!));
        var pushed = JsonNode.Parse(
            await pushResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(HttpStatusCode.Created, pushResponse.StatusCode);

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = signing.ClientId,
            [AuthorizationRequest.Parameters.RequestUri] =
                pushed[PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>(),
        });

        var tokenResponse = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = code,
                [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [TokenRequest.Parameters.CodeVerifier] = verifier,
                [ClientRequest.Parameters.ClientId] = signing.ClientId,
                [ClientRequest.Parameters.ClientSecret] = signing.ClientSecret,
            },
            otherKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint));

        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var body = JsonNode.Parse(
            await tokenResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidDPoPProof, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
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

    /// <summary>
    /// RFC 9126 section 3: "Request parameters required by a given client authentication method are included in the
    /// "application/x-www-form-urlencoded" request directly and are the only parameters other than "request" in the
    /// form body". A client_secret_basic client authenticates in the header, so its form holds the object alone, and
    /// the pushed request is accepted with 201.
    /// </summary>
    [Fact]
    public async Task StrictProcessing_PushedObjectAlone_WithBasicAuthentication_IsAccepted()
    {
        await using var host = CreateStrictHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var signing = await RegisterBasicSigningClientAsync(client, discovery);

        var response = await PushObjectAloneAsync(
            client, discovery, signing, await SignRequestObjectAsync(discovery, signing, GeneratePkcePair().Challenge));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>
    /// The object is read for the client that authenticated, so an object another client signed is refused as
    /// invalid_request_object, the client_id inside it not being the one the request is for (RFC 9101 section 6.3).
    /// </summary>
    [Fact]
    public async Task StrictProcessing_PushedObjectOfAnotherClient_IsAnInvalidRequestObject()
    {
        await using var host = CreateStrictHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(client, discovery);
        var other = await RegisterBasicSigningClientAsync(client, discovery);

        var response = await PushObjectAloneAsync(
            client, discovery, poster, await SignRequestObjectAsync(discovery, other, GeneratePkcePair().Challenge));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// Pushes <paramref name="requestObject"/> as the only form parameter, <paramref name="poster"/> authenticating
    /// with HTTP Basic.
    /// </summary>
    private static async Task<HttpResponseMessage> PushObjectAloneAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        SigningClient poster,
        string requestObject)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.PushedAuthorizationRequestEndpoint!)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.Request] = requestObject,
            }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Basic,
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                Uri.EscapeDataString(poster.ClientId) + ":" + Uri.EscapeDataString(poster.ClientSecret))));

        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A client that must sign its request objects and authenticates with client_secret_basic.
    /// </summary>
    private static async Task<SigningClient> RegisterBasicSigningClientAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
            [RegistrationMembers.Jwks] = JsonSerializer.SerializeToNode(PublicJwksFor(key)),
            [RegistrationMembers.RequireSignedRequestObject] = true,
        });

        return new SigningClient(
            registered[ClientRegistrationResponse.Parameters.ClientId]!.GetValue<string>(),
            registered[ClientRegistrationResponse.Parameters.ClientSecret]!.GetValue<string>(),
            key);
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
    private static async Task<string> SignRequestObjectAsync(
        DiscoveryDocument discovery,
        SigningClient signing,
        string challenge)
    {
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
