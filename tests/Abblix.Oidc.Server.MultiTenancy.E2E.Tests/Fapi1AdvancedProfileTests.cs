// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant holding its clients to FAPI 1.0 Advanced refuses at the authorization endpoint what that profile does
/// not admit, and lets through the same request with the one thing it lacked put back.
/// </summary>
/// <remarks>
/// Every request reaches the endpoint unauthenticated, so one the endpoint accepts is sent on to the login page;
/// that redirect is what tells an accepted request from a refused one.
/// </remarks>
public sealed class Fapi1AdvancedProfileTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string ClientId = "fapi1-client";
    private const string LoginPath = "/login";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri the client registers; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private static readonly RsaJsonWebKey ClientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private WebApplication? _app;
    private HttpClient? _http;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(_ => { });
        builder.Services.Configure<OidcOptions>(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(Host + Acme),
            DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced,
            Clients = [Client()],
            LoginUri = new Uri(LoginPath, UriKind.Relative),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    private static ClientInfo Client() => new(ClientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
        AllowedGrantTypes = [GrantTypes.AuthorizationCode],
        AllowedResponseTypes = [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
        RedirectUris = [new Uri(RedirectUri)],
        // FAPI 1.0 Part 2 asks PKCE only of a pushed request, and these requests go by value
        PkceRequired = false,
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
        AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
    };

    /// <summary>
    /// The request a conformant client sends: code with the JWT response mode, the openid scope and a nonce, in a
    /// request object addressed to the issuer, signed PS256, living five minutes.
    /// </summary>
    private static JsonObject ConformantRequest() => new()
    {
        [AuthorizationRequest.Parameters.ClientId] = ClientId,
        [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
        [AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.Jwt,
        [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
        [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
        [AuthorizationRequest.Parameters.State] = "state-1",
        [AuthorizationRequest.Parameters.Nonce] = "nonce-1",
    };

    /// <summary>
    /// Signs <paramref name="parameters"/> into a request object and sends it to the authorization endpoint by
    /// value, with the client_id and response_type duplicates RFC 9101 section 5 and OpenID Connect Core section 6.1
    /// expect outside it.
    /// </summary>
    private async Task<HttpResponseMessage> AuthorizeAsync(
        JsonObject parameters,
        string algorithm = SigningAlgorithms.PS256,
        bool addressedToTheIssuer = true)
    {
        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = algorithm, KeyId = ClientKey.KeyId },
            Payload =
            {
                Issuer = ClientId,
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
        if (addressedToTheIssuer)
            token.Payload.Audiences = [Host + Acme];

        foreach (var (name, value) in parameters)
            token.Payload.Json[name] = value?.DeepClone();

        var requestObject = await _app!.Services.GetRequiredService<IJsonWebTokenCreator>()
            .IssueAsync(token, ClientKey);

        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = ClientId;
        query[AuthorizationRequest.Parameters.ResponseType] =
            parameters[AuthorizationRequest.Parameters.ResponseType]!.GetValue<string>();
        query[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        query[AuthorizationRequest.Parameters.Request] = requestObject;

        return await _http!.GetAsync(Acme + "/connect/authorize?" + query, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The error the response carries, wherever the endpoint put it: in the redirect's query or fragment, inside
    /// the JWT a JWT response mode wraps it in, or in the body of a response sent to the browser; null when it
    /// carries none.
    /// </summary>
    private static async Task<string?> ErrorOf(HttpResponseMessage response)
    {
        if (response.Headers.Location is { } location)
        {
            var parameters = HttpUtility.ParseQueryString(
                location.IsAbsoluteUri ? location.Query.TrimStart('?') + "&" + location.Fragment.TrimStart('#') : "");

            if (parameters[ResponseParameters.Error] is { } error)
                return error;

            if (parameters[ResponseParameters.Response] is { } wrapped)
            {
                var payload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(wrapped.Split('.')[1]));
                return JsonNode.Parse(payload)![ResponseParameters.Error]?.GetValue<string>();
            }

            return null;
        }

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return body.HasValue() && JsonNode.Parse(body) is JsonObject json
            ? json[ErrorResponse.Parameters.Error]?.GetValue<string>()
            : null;
    }

    /// <summary>
    /// What an accepted request ends in here: a redirect to the login page, since nobody is signed in.
    /// </summary>
    private static async Task AssertSentToLogin(HttpResponseMessage response)
    {
        var location = Assert.IsType<Uri>(response.Headers.Location);
        var path = location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0];
        Assert.True(path.EndsWith(LoginPath, StringComparison.Ordinal), $"{response.StatusCode}, error {await ErrorOf(response)}");
    }

    /// <summary>
    /// The conformant request is accepted, which is what makes every refusal below the refusal of the one thing
    /// changed in it.
    /// </summary>
    [Fact]
    public async Task TheConformantRequest_IsAccepted()
    {
        await AssertSentToLogin(await AuthorizeAsync(ConformantRequest()));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2 requires "the response_type value code id_token, or the response_type value
    /// code in conjunction with the response_mode value jwt", so plain code, whose response nothing signs, is
    /// refused.
    /// </summary>
    [Fact]
    public async Task PlainCode_WithoutTheJwtResponseMode_IsRefused()
    {
        var request = ConformantRequest();
        request.Remove(AuthorizationRequest.Parameters.ResponseMode);

        Assert.Equal(ErrorCodes.UnsupportedResponseType, await ErrorOf(await AuthorizeAsync(request)));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2 requires "the aud claim in the request object to be, or to be an array
    /// containing, the OP's Issuer Identifier URL", so an object naming no audience is refused.
    /// </summary>
    [Fact]
    public async Task ARequestObjectWithoutAudience_IsRefused()
    {
        Assert.Equal(
            ErrorCodes.InvalidRequestObject,
            await ErrorOf(await AuthorizeAsync(ConformantRequest(), addressedToTheIssuer: false)));
    }
}
