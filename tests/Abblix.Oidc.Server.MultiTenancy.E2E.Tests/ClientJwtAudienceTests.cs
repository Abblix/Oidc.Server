// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A request object and a login_hint_token carrying an audience must name this server, which RFC 7519 section 4.1.3
/// has reject a JWT whose aud it does not "identify itself with", and this server identifies itself by its issuer
/// identifier: for a signed request object RFC 9101 section 4 says "The value of "aud" should be the value of the
/// authorization server (AS) "issuer"", OpenID Connect Core 1.0 section 6.1 "The aud value SHOULD be or include the
/// OP's Issuer Identifier URL", and RFC 9126 section 3 applies the JAR rules to a pushed one; for a login_hint_token,
/// whose details CIBA Core 1.0 section 7.1 leaves to the deployment, the issuer alone is this server's policy. A host serving its one tenant without <c>UseMultiTenancy()</c> answers on whatever name a request
/// uses, so an audience spelled from the request would match an object a client signed for another server reached by
/// the same path; each one naming the endpoint as the request spells it is refused, and the same one naming the issuer
/// is served, so the refusal is the audience's and not the client's or the endpoint's.
/// </summary>
public sealed class ClientJwtAudienceTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "signing-client";
    private const string ClientSecret = "signing-client-secret";
    private const string RedirectUri = "https://client.example.com/callback";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // A name the host is reached by inside its own network, and the issuer's host on another port
    private const string InternalName = "oidc-svc:8080";
    private const string AnotherPort = "auth.example.com:8443";

    private static readonly RsaJsonWebKey ClientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    [Theory]
    [InlineData(InternalName)]
    [InlineData(AnotherPort)]
    public async Task ARequestObjectAtTheAuthorizationEndpoint_NamesTheIssuer(string requestHost)
    {
        await using var app = await StartAsync();
        using var http = ClientOn(app, requestHost);
        var endpoint = await EndpointAsync(http, ConfigurationResponse.Parameters.AuthorizationEndpoint);

        using var refused = await AuthorizeAsync(http, endpoint, $"https://{requestHost}{endpoint}");
        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorOfAsync(refused));

        // Served as far as the end-user's sign-in, the tenant's login page, since nobody is signed in
        using var served = await AuthorizeAsync(http, endpoint, Issuer);
        Assert.Null(await ErrorOfAsync(served));
        Assert.Equal(
            Tenant.LoginUri!.OriginalString,
            new Uri(new Uri(Issuer), served.Headers.Location!).AbsolutePath);
    }

    [Theory]
    [InlineData(InternalName)]
    [InlineData(AnotherPort)]
    public async Task ARequestObjectAtThePushedAuthorizationEndpoint_NamesTheIssuer(string requestHost)
    {
        await using var app = await StartAsync();
        using var http = ClientOn(app, requestHost);
        var endpoint = await EndpointAsync(http, ConfigurationResponse.Parameters.PushedAuthorizationRequestEndpoint);

        using var refused = await PushAsync(http, endpoint, $"https://{requestHost}{endpoint}");
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorOfAsync(refused));

        using var served = await PushAsync(http, endpoint, Issuer);
        Assert.Equal(HttpStatusCode.Created, served.StatusCode);
    }

    [Theory]
    [InlineData(InternalName)]
    [InlineData(AnotherPort)]
    public async Task ALoginHintToken_NamesTheIssuer(string requestHost)
    {
        await using var app = await StartAsync();
        using var http = ClientOn(app, requestHost);
        var endpoint = await EndpointAsync(http, ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint);

        using var refused = await InitiateAsync(http, endpoint, $"https://{requestHost}{endpoint}");
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, await ErrorOfAsync(refused));

        using var served = await InitiateAsync(http, endpoint, Issuer);
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
    }

    private static async Task<HttpResponseMessage> AuthorizeAsync(HttpClient http, string endpoint, string audience)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = ClientId;
        query[AuthorizationRequest.Parameters.Request] = await RequestObjectAsync(audience);
        return await http.GetAsync($"{endpoint}?{query}", TestContext.Current.CancellationToken);
    }

    private static async Task<HttpResponseMessage> PushAsync(HttpClient http, string endpoint, string audience)
        => await http.PostAsync(
            endpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.Request] = await RequestObjectAsync(audience),
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

    private static async Task<HttpResponseMessage> InitiateAsync(HttpClient http, string endpoint, string audience)
        => await http.PostAsync(
            endpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHintToken] = await SignAsync(Token(audience)),
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

    /// <summary>
    /// A request object carrying a whole code flow request, addressed to <paramref name="audience"/>.
    /// </summary>
    private static async Task<string> RequestObjectAsync(string audience)
    {
        var token = Token(audience);
        token.Payload.Json[AuthorizationRequest.Parameters.ClientId] = ClientId;
        token.Payload.Json[AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code;
        token.Payload.Json[AuthorizationRequest.Parameters.RedirectUri] = RedirectUri;
        token.Payload.Json[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        token.Payload.Json[AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N");
        token.Payload.Json[AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge;
        token.Payload.Json[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;
        return await SignAsync(token);
    }

    private static JsonWebToken Token(string audience)
    {
        var now = TimeProvider.System.GetUtcNow();
        return new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, KeyId = ClientKey.KeyId },
            Payload =
            {
                Issuer = ClientId,
                Audiences = [audience],
                JwtId = Guid.NewGuid().ToString("N"),
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
    }

    private static Task<string> SignAsync(JsonWebToken token)
        => JwtServices.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, ClientKey);

    private static readonly IServiceProvider JwtServices = new ServiceCollection()
        .AddSingleton(TimeProvider.System)
        .AddLogging()
        .AddJsonWebTokens()
        .BuildServiceProvider();

    /// <summary>
    /// The path of the endpoint the discovery document fetched on the client's host publishes as
    /// <paramref name="member"/>.
    /// </summary>
    private static async Task<string> EndpointAsync(HttpClient http, string member)
    {
        using var discovery = await http.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        discovery.EnsureSuccessStatusCode();
        var document = JsonNode.Parse(await discovery.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        return new Uri(document[member]!.GetValue<string>()).AbsolutePath;
    }

    /// <summary>
    /// The error a response carries: in the query of the redirect it answers with, or in its body.
    /// </summary>
    private static async Task<string?> ErrorOfAsync(HttpResponseMessage response)
    {
        if (response.Headers.Location is { } location)
        {
            var query = location.IsAbsoluteUri ? location.Query : new Uri(new Uri(Issuer), location).Query;
            return HttpUtility.ParseQueryString(query)[ResponseParameters.Error];
        }

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return body.Length == 0 ? null : JsonNode.Parse(body)?[ErrorResponse.Parameters.Error]?.GetValue<string>();
    }

    private static HttpClient ClientOn(WebApplication app, string requestHost)
    {
        var http = app.GetTestClient();
        http.BaseAddress = new Uri($"https://{requestHost}");
        return http;
    }

    /// <summary>
    /// A host serving its one tenant, at an issuer without a path, without <c>UseMultiTenancy()</c>, so it answers on
    /// whatever host name a request uses.
    /// </summary>
    private static async Task<WebApplication> StartAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddBackChannelAuthentication();
        // The authorization endpoint reads the end-user's session before it answers
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.BackChannelAuthentication;
            options.Tenants.Add(Tenant);
        });
        builder.Services.Replace(
            ServiceDescriptor.Scoped<IUserDeviceAuthenticationHandler, ReachableUserDeviceHandler>());

        var app = builder.Build();
        app.UseRouting();
        app.UseCors();
        app.UseAuthentication();
        app.MapOidcEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static readonly TenantDefinition Tenant = new()
    {
        Id = "acme",
        Issuer = new Uri(Issuer),
        LoginUri = new Uri("/login", UriKind.Relative),
        Clients =
        [
            new ClientInfo(ClientId)
            {
                ClientSecrets =
                [
                    new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
                ],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
                AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.Ciba],
                RedirectUris = [new Uri(RedirectUri)],
                PkceRequired = true,
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
            },
        ],
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    /// <summary>
    /// The end-user a login_hint_token names is always reachable on their device, so a decoupled authentication starts.
    /// </summary>
    private sealed class ReachableUserDeviceHandler(TimeProvider clock) : IUserDeviceAuthenticationHandler
    {
        public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
            TenantDefinition tenant,
            ValidBackChannelAuthenticationRequest request)
            => Task.FromResult<Result<AuthSession, OidcError>>(
                new AuthSession("alice", Guid.NewGuid().ToString("N"), clock.GetUtcNow(), "local"));
    }
}
