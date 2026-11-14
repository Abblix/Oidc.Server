// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Net;
using System.Text.Json.Nodes;
using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// CIBA Core 1.0 section 7.2 has the server "Authenticate the Client per the authentication method registered or
/// configured for its client_id" before it validates the signed authentication request, so the request object is
/// judged under the security profile of the client that authenticated from its first layer. At a tenant holding its
/// clients to no profile, a client held to FAPI 1.0 Advanced has a request object encrypted with RSA1_5 (FAPI 1.0
/// Part 2 section 8.6.1: "For JWE, both clients and authorization servers shall not use the RSA1_5 algorithm")
/// refused before any of the tenant's decryption keys is read, while a client held to no profile has the same object
/// decrypted and accepted.
/// </summary>
public sealed class CibaRequestObjectProfileTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string AuthorizePath = "/connect/bc-authorize";
    private const string FapiClientId = "fapi-ciba-client";
    private const string PlainClientId = "plain-ciba-client";
    private const string PublicClientId = "public-browser-client";
    private const string LoginHint = "alice";

    private static readonly RsaJsonWebKey ClientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    /// <summary>
    /// The tenant's key a client encrypts its request objects to.
    /// </summary>
    private static readonly RsaJsonWebKey EncryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);

    private readonly DecryptionKeyReads _decryptionKeyReads = new();
    private WebApplication? _app;
    private HttpClient? _http;

    private static readonly TenantDefinition Tenant = new()
    {
        Id = "acme",
        Issuer = new Uri(Host + Acme),
        Clients =
        [
            Client(FapiClientId, ClientSecurityProfile.Fapi1Advanced),
            Client(PlainClientId, null),
            // A browser client of another flow, which authenticates with the method "none"
            new ClientInfo(PublicClientId)
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                AllowedResponseTypes = [[ResponseTypes.Code]],
                RedirectUris = [new Uri("https://spa.example.com/callback")],
            },
        ],
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        EncryptionKeys = [EncryptionKey],
    };

    private static ClientInfo Client(string clientId, ClientSecurityProfile? profile) => new(clientId)
    {
        SecurityProfile = profile,
        TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
        AllowedGrantTypes = [GrantTypes.Ciba],
        AllowedResponseTypes = [],
        BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
        IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
        AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
        // FAPI 1.0 Part 2 section 8.2: access tokens are sender-constrained via MTLS only
        TlsClientCertificateBoundAccessTokens = true,
    };

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddBackChannelAuthentication();
        // A deployment that opted in to RSA1_5 for its legacy peers, which the profile then forbids its FAPI clients
        builder.Services.AddRsaPkcs1KeyManagement();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.BackChannelAuthentication;
            // FAPI 1.0 Part 2 section 8.6 holds what the server signs to PS256 or ES256
            options.ServiceTokens.AccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RefreshToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RegistrationAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.InitialAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
        });
        builder.Services.Configure<OidcOptions>(options => options.Tenants.Add(Tenant));
        builder.Services.Replace(
            ServiceDescriptor.Scoped<IUserDeviceAuthenticationHandler, ReachableUserDeviceHandler>());
        builder.Services.AddSingleton(_decryptionKeyReads);
        builder.Services.Decorate<IAuthServiceKeysProvider, CountingDecryptionKeys>();

        _app = builder.Build();
        _app.UseMultiTenancy();
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

    /// <summary>
    /// A request object encrypted with RSA1_5 is refused for the client held to FAPI 1.0 Advanced without one decryption
    /// key read, and decrypted and accepted for the client held to none; the FAPI client's object encrypted with
    /// RSA-OAEP-256 is decrypted and accepted, so its refusal is the refusal of the layer and not of the client.
    /// </summary>
    [Theory]
    [InlineData(FapiClientId, EncryptionAlgorithms.KeyManagement.Rsa1_5, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject, false)]
    [InlineData(FapiClientId, EncryptionAlgorithms.KeyManagement.RsaOaep256, HttpStatusCode.OK, null, true)]
    [InlineData(PlainClientId, EncryptionAlgorithms.KeyManagement.Rsa1_5, HttpStatusCode.OK, null, true)]
    public async Task ARequestObjectLayer_IsJudgedUnderTheAuthenticatedClientsProfile(
        string clientId, string keyManagement, HttpStatusCode expectedStatus, string? expectedError, bool decrypted)
    {
        using var response = await InitiateAsync(clientId, keyManagement, authenticated: true);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(expectedStatus == response.StatusCode, $"{response.StatusCode}: {body}");
        Assert.Equal(expectedError, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
        Assert.Equal(decrypted, _decryptionKeyReads.Count > 0);
    }

    /// <summary>
    /// A caller that does not authenticate is answered invalid_client (CIBA Core 1.0 section 13, HTTP 401, "Client
    /// authentication failed") before its request object is read, so it cannot have the server decrypt one.
    /// </summary>
    [Fact]
    public async Task AnUnauthenticatedCaller_IsInvalidClient_BeforeItsObjectIsDecrypted()
    {
        using var response = await InitiateAsync(PlainClientId, EncryptionAlgorithms.KeyManagement.Rsa1_5, authenticated: false);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClient, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
        Assert.Equal(0, _decryptionKeyReads.Count);
    }

    /// <summary>
    /// CIBA Core 1.0 section 7.1: "The Client MUST authenticate to the Backchannel Authentication Endpoint using the
    /// authentication method registered for its client_id". A caller naming a client registered with the method
    /// "none" authenticates nobody, so it is answered unauthorized_client (section 13, "The Client is not authorized to
    /// use this authentication flow") before its request object is read.
    /// </summary>
    [Fact]
    public async Task ACallerNamingAPublicClient_IsUnauthorized_BeforeItsObjectIsDecrypted()
    {
        using var response = await InitiateAsync(
            PublicClientId, EncryptionAlgorithms.KeyManagement.Rsa1_5, authenticated: false, signedBy: PlainClientId);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(HttpStatusCode.BadRequest == response.StatusCode, $"{response.StatusCode}: {body}");
        Assert.Equal(ErrorCodes.UnauthorizedClient, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
        Assert.Equal(0, _decryptionKeyReads.Count);
    }

    /// <summary>
    /// CIBA Core 1.0 section 7.1.1: the request object's "Issuer claim MUST be the client_id of the OAuth Client". An
    /// object another client issued, sent by a client that authenticated as itself, is refused.
    /// </summary>
    [Fact]
    public async Task ARequestObjectIssuedByAnotherClient_IsRefused()
    {
        using var response = await InitiateAsync(
            PlainClientId, EncryptionAlgorithms.KeyManagement.RsaOaep256, authenticated: true, signedBy: FapiClientId);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(HttpStatusCode.BadRequest == response.StatusCode, $"{response.StatusCode}: {body}");
        Assert.Equal(ErrorCodes.InvalidRequestObject, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// CIBA Core 1.0 section 7.1.1: "The JWT MUST also contain the following [RFC7519] registered claims: aud ... iss ...
    /// exp ... iat ... nbf ... jti". A signed authentication request lacking any of them is refused; the same request
    /// carrying all of them is accepted.
    /// </summary>
    [Theory]
    [InlineData(null, HttpStatusCode.OK, null)]
    [InlineData(JwtClaimTypes.Issuer, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    [InlineData(JwtClaimTypes.Audience, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    [InlineData(JwtClaimTypes.ExpiresAt, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    [InlineData(JwtClaimTypes.IssuedAt, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    [InlineData(JwtClaimTypes.NotBefore, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    [InlineData(JwtClaimTypes.JwtId, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    public async Task ASignedRequestLackingARegisteredClaim_IsRefused(
        string? omitted, HttpStatusCode expectedStatus, string? expectedError)
    {
        var requestObject = await SignedRequestAsync(PlainClientId, token =>
        {
            if (omitted is null)
                return;

            token.Payload.Json.Remove(omitted);
            // An object without iss still names its client, so it is refused for the claim and not for an unknown signer
            if (omitted == JwtClaimTypes.Issuer)
                token.Payload.Json[IanaClaimTypes.ClientId] = PlainClientId;
        });

        if (omitted is not null)
            Assert.False(PayloadOf(requestObject).ContainsKey(omitted), $"the object still carries {omitted}");

        using var response = await PostAsync(PlainClientId, requestObject);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(expectedStatus == response.StatusCode, $"{response.StatusCode}: {body}");
        Assert.Equal(expectedError, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// CIBA Core 1.0 section 7.1.1: "The Audience claim MUST contain the value of the Issuer Identifier for the OP". An
    /// object addressed to the backchannel authentication endpoint alone is refused; one whose audience contains the
    /// issuer beside another value is accepted.
    /// </summary>
    [Theory]
    [InlineData(new[] { Host + Acme + AuthorizePath }, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    [InlineData(new[] { "https://elsewhere.example.com", Host + Acme }, HttpStatusCode.OK, null)]
    public async Task TheAudience_MustContainTheIssuer(
        string[] audiences, HttpStatusCode expectedStatus, string? expectedError)
    {
        var requestObject = await SignedRequestAsync(PlainClientId, token => token.Payload.Audiences = audiences);

        using var response = await PostAsync(PlainClientId, requestObject);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(expectedStatus == response.StatusCode, $"{response.StatusCode}: {body}");
        Assert.Equal(expectedError, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// A signed, unencrypted authentication request of <paramref name="clientId"/> carrying every claim CIBA Core 1.0
    /// section 7.1.1 lists, changed by <paramref name="change"/> before it is signed.
    /// </summary>
    private async Task<string> SignedRequestAsync(string clientId, Action<JsonWebToken> change)
    {
        var token = RequestToken(clientId);
        change(token);
        return await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, ClientKey);
    }

    private static JsonObject PayloadOf(string jwt)
        => JsonNode.Parse(Base64Url.DecodeFromChars(jwt.Split('.')[1]))!.AsObject();

    /// <summary>
    /// Posts <paramref name="requestObject"/> beside the private_key_jwt assertion of <paramref name="clientId"/>.
    /// </summary>
    private async Task<HttpResponseMessage> PostAsync(string clientId, string requestObject)
        => await _http!.PostAsync(
            Acme + AuthorizePath,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [CibaParameters.Request] = requestObject,
                [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
                [ClientRequest.Parameters.ClientAssertion] = await ClientAssertionAsync(clientId),
            }),
            TestContext.Current.CancellationToken);

    /// <summary>
    /// Posts a signed authentication request (CIBA Core 1.0 section 7.1.1) of <paramref name="clientId"/>, encrypted to
    /// the tenant with <paramref name="keyManagement"/>, beside that client's private_key_jwt assertion or, when not
    /// <paramref name="authenticated"/>, beside its client_id alone; the object is issued by
    /// <paramref name="signedBy"/> where it is named.
    /// </summary>
    private async Task<HttpResponseMessage> InitiateAsync(
        string clientId, string keyManagement, bool authenticated, string? signedBy = null)
    {
        var form = new Dictionary<string, string>
        {
            [CibaParameters.Request] = await RequestObjectAsync(signedBy ?? clientId, keyManagement),
        };
        if (authenticated)
        {
            form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
            form[ClientRequest.Parameters.ClientAssertion] = await ClientAssertionAsync(clientId);
        }
        else
        {
            form[ClientRequest.Parameters.ClientId] = clientId;
        }

        return await _http!.PostAsync(
            Acme + AuthorizePath, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The request parameters signed PS256 by <paramref name="clientId"/> with the registered claims CIBA Core 1.0
    /// section 7.1.1 requires, encrypted to the tenant's key with <paramref name="keyManagement"/>.
    /// </summary>
    private async Task<string> RequestObjectAsync(string clientId, string keyManagement)
        => await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            RequestToken(clientId), ClientKey, EncryptionKey.Sanitize(includePrivateKeys: false), keyManagement);

    /// <summary>
    /// The request parameters of <paramref name="clientId"/> with the registered claims CIBA Core 1.0 section 7.1.1
    /// requires, to be signed PS256.
    /// </summary>
    private static JsonWebToken RequestToken(string clientId)
    {
        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.PS256, KeyId = ClientKey.KeyId },
            Payload =
            {
                Issuer = clientId,
                Audiences = [Host + Acme],
                JwtId = Guid.NewGuid().ToString("N"),
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
        token.Payload.Json[CibaParameters.Scope] = Scopes.OpenId;
        token.Payload.Json[CibaParameters.LoginHint] = LoginHint;
        return token;
    }

    /// <summary>
    /// A private_key_jwt client authentication assertion (OpenID Connect Core section 9) addressed to the issuer.
    /// </summary>
    private async Task<string> ClientAssertionAsync(string clientId)
    {
        var now = TimeProvider.System.GetUtcNow();
        return await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.PS256, KeyId = ClientKey.KeyId },
                Payload =
                {
                    Issuer = clientId,
                    Subject = clientId,
                    Audiences = [Host + Acme],
                    JwtId = Guid.NewGuid().ToString("N"),
                    IssuedAt = now,
                    ExpiresAt = now.AddMinutes(1),
                },
            },
            ClientKey);
    }

    /// <summary>
    /// How many of the tenant's private decryption keys the server has read.
    /// </summary>
    private sealed class DecryptionKeyReads
    {
        private int _count;

        public int Count => Volatile.Read(ref _count);

        public void Add() => Interlocked.Increment(ref _count);
    }

    /// <summary>
    /// The server's keys, noting every private decryption key handed out, which is what opening a JWE layer takes.
    /// </summary>
    private sealed class CountingDecryptionKeys(IAuthServiceKeysProvider inner, DecryptionKeyReads reads)
        : IAuthServiceKeysProvider
    {
        public async IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(TenantDefinition tenant, bool includePrivateKeys = false)
        {
            await foreach (var key in inner.GetEncryptionKeys(tenant, includePrivateKeys))
            {
                if (includePrivateKeys)
                    reads.Add();
                yield return key;
            }
        }

        public IAsyncEnumerable<JsonWebKey> GetSigningKeys(TenantDefinition tenant, bool includePrivateKeys = false)
            => inner.GetSigningKeys(tenant, includePrivateKeys);
    }

    /// <summary>
    /// The end user's device, reached at once.
    /// </summary>
    private sealed class ReachableUserDeviceHandler(TimeProvider clock) : IUserDeviceAuthenticationHandler
    {
        public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
            TenantDefinition tenant,
            ValidBackChannelAuthenticationRequest request)
            => Task.FromResult<Result<AuthSession, OidcError>>(new AuthSession(
                request.Model.LoginHint!, Guid.NewGuid().ToString("N"), clock.GetUtcNow(), "local"));
    }
}
