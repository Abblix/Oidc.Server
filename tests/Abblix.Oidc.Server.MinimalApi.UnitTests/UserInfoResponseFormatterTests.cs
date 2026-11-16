// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt;
using System.Text.Json.Nodes;
using Microsoft.Net.Http.Headers;
using System.Linq;
using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Xunit;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// The status the UserInfo endpoint, a protected resource, gives each error code RFC 6750 section 3.1 defines.
/// </summary>
/// <remarks>
/// The twin of the MVC suite's <c>UserInfoResponseFormatterTests</c>.
/// </remarks>
public class UserInfoResponseFormatterTests
{
    private static readonly TenantDefinition Served = new() { Id = "main", Issuer = new Uri("https://auth.example.com") };

    /// <summary>Tells every request it is served by <paramref name="tenant"/>.</summary>
    private sealed class ServedBy(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }

    private static async Task<HttpResultRunner.Response> FormatErrorAsync(string errorCode)
    {
        // The JWT formatter and the options serve only a successful response, which no test here formats
        var formatter = new UserInfoResponseFormatter(TimeProvider.System, null!, new ServedBy(Served), new FapiInteractionIdResolver(NullLogger<FapiInteractionIdResolver>.Instance));

        Result<UserInfoFoundResponse, OidcError> response = new OidcError(errorCode, "the description");
        return await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), response));
    }

    /// <summary>
    /// RFC 9449 section 7.1: the DPoP challenge names in algs the algorithms a new proof may use. An error naming the
    /// algorithms of the token's client is challenged with exactly those; one naming none - a client whose profile
    /// refuses DPoP (FAPI 1.0 Part 2 section 8.2) - is challenged with Bearer alone.
    /// </summary>
    [Theory]
    [InlineData(new[] { "ES256", "PS256" }, new[] { "DPoP", "Bearer" })]
    [InlineData(new string[0], new[] { "Bearer" })]
    public async Task The_challenge_advertises_the_algorithms_the_error_names(string[] admitted, string[] schemes)
    {
        var formatter = new UserInfoResponseFormatter(TimeProvider.System, null!, new ServedBy(Served), new FapiInteractionIdResolver(NullLogger<FapiInteractionIdResolver>.Instance));
        Result<UserInfoFoundResponse, OidcError> refused =
            new OidcError(ErrorCodes.InvalidToken, "presented with the Bearer scheme") { DPoPAlgorithmsAdmitted = admitted };

        var response = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), refused));

        var challenges = response.Headers[HeaderNames.WWWAuthenticate].Select(ChallengeReader.Parse).ToArray();
        Assert.Equal(schemes, challenges.Select(challenge => challenge.Scheme));
        if (admitted.Length > 0)
            Assert.Equal(admitted, challenges[0].Parameters["algs"].Split(' '));
    }

    /// <summary>
    /// RFC 6750 section 3.1, invalid_token: "The access token provided is expired, revoked, malformed, or invalid for
    /// other reasons". A response the token's client cannot be sent, its key set holding only keys its profile forbids,
    /// is answered so with 401 rather than as a server error.
    /// </summary>
    [Fact]
    public async Task A_response_the_clients_key_set_cannot_receive_is_an_invalid_token()
    {
        var client = new ClientInfo("client") { UserInfoSignedResponseAlgorithm = "PS256" };
        // The formatter refuses the token, as it does for a key set the profile leaves nothing in
        var clientJwtFormatter = new Mock<IClientJwtFormatter>();
        clientJwtFormatter
            .Setup(f => f.FormatAsync(Served, It.IsAny<JsonWebToken>(), client, It.IsAny<ClientJwtEncryption>()))
            .ReturnsAsync(new OidcError(ErrorCodes.UnauthorizedClient, "no key to encrypt to"));
        var formatter = new UserInfoResponseFormatter(
            TimeProvider.System, clientJwtFormatter.Object, new ServedBy(Served), new FapiInteractionIdResolver(NullLogger<FapiInteractionIdResolver>.Instance));
        Result<UserInfoFoundResponse, OidcError> found =
            new UserInfoFoundResponse(new JsonObject(), client, Served.Issuer.OriginalString)
            {
                PresentedScheme = AccessTokenScheme.Bearer,
            };

        var response = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), found));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        // RFC 9449 section 7.2: the refusal is answered on the challenge of the scheme the token was presented with
        var challenges = response.Headers[HeaderNames.WWWAuthenticate].Select(ChallengeReader.Parse).ToArray();
        var bearer = Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.Bearer);
        var dpop = Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.DPoP);
        Assert.Equal(ErrorCodes.InvalidToken, bearer.Parameters["error"]);
        Assert.DoesNotContain("error", dpop.Parameters.Keys);
    }

    /// <summary>
    /// RFC 6750 section 3.1: invalid_request is answered with 400, invalid_token with 401. A client answered 401 for
    /// a token sent the way its security profile refuses would renew the token and send it the same way again.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, StatusCodes.Status400BadRequest)]
    [InlineData(ErrorCodes.InvalidToken, StatusCodes.Status401Unauthorized)]
    public async Task An_error_takes_the_status_rfc_6750_gives_its_code(string errorCode, int expectedStatusCode)
    {
        var response = await FormatErrorAsync(errorCode);

        Assert.Equal(expectedStatusCode, response.StatusCode);
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 5.3.2: "The response MAY be encrypted without also being signed", and "If the
    /// UserInfo Response is signed and/or encrypted, then the Claims are returned in a JWT". A client that registered
    /// userinfo_encrypted_response_alg alone is answered with a JWT, not the plain document.
    /// </summary>
    [Fact]
    public async Task An_encrypted_only_response_is_a_jwt()
    {
        var client = new ClientInfo("client")
        {
            UserInfoEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        };
        var clientJwtFormatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        clientJwtFormatter
            .Setup(f => f.FormatAsync(
                Served,
                It.Is<JsonWebToken>(token => token.Header.Algorithm == SigningAlgorithms.None),
                client,
                It.Is<ClientJwtEncryption>(encryption =>
                    encryption.KeyManagementAlgorithm == EncryptionAlgorithms.KeyManagement.RsaOaep256)))
            .ReturnsAsync("header.encrypted-key.iv.ciphertext.tag");
        var formatter = new UserInfoResponseFormatter(
            TimeProvider.System, clientJwtFormatter.Object, new ServedBy(Served), new FapiInteractionIdResolver(NullLogger<FapiInteractionIdResolver>.Instance));
        Result<UserInfoFoundResponse, OidcError> found =
            new UserInfoFoundResponse(new JsonObject(), client, Served.Issuer.OriginalString);

        var response = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), found));

        Assert.Equal(StatusCodes.Status200OK, response.StatusCode);
        Assert.StartsWith(MediaTypes.Jwt, response.Headers.ContentType.ToString());
    }

    /// <summary>
    /// The response a client that registered userinfo_encrypted_response_alg alone receives is the claims encrypted to
    /// its key, as RFC 7519 section 3 has an encrypted JWT ("the JWT Claims Set being the plaintext encrypted by the
    /// JWE"), with no unsigned JWS inside: the client opens it with its own key and reads the claims, and this
    /// library's validator accepts it where signatures are not required.
    /// </summary>
    [Fact]
    public async Task An_encrypted_only_response_opens_with_the_clients_key()
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton(services, TimeProvider.System);
        Microsoft.Extensions.DependencyInjection.LoggingServiceCollectionExtensions.AddLogging(services);
        Abblix.Jwt.ServiceCollectionExtensions.AddJsonWebTokens(services);
        await using var provider = Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions
            .BuildServiceProvider(services);
        T Get<T>() where T : notnull
            => Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetRequiredService<T>(provider);

        var tenant = new TenantDefinition { Id = "main", Issuer = new Uri("https://auth.example.com") };
        var tenantAccessor = Mock.Of<ITenantAccessor>(accessor => accessor.Current == new TenantContext { Tenant = tenant });
        var client = new ClientInfo("client")
        {
            UserInfoEncryptedResponseAlgorithm = Abblix.Jwt.EncryptionAlgorithms.KeyManagement.RsaOaep256,
        };
        var clientKey = Abblix.Jwt.JsonWebKeyFactory.CreateRsa(Abblix.Jwt.PublicKeyUsages.Encryption);
        var clientKeys = new Mock<IClientKeysProvider>();
        clientKeys.Setup(k => k.GetEncryptionKeys(client))
            .Returns(new Abblix.Jwt.JsonWebKey[] { clientKey }.ToAsyncEnumerable());
        var serviceKeys = new Mock<Abblix.Oidc.Server.Common.Interfaces.IAuthServiceKeysProvider>();
        serviceKeys.Setup(k => k.GetSigningKeys(It.IsAny<TenantDefinition>(), It.IsAny<bool>()))
            .Returns(System.Linq.AsyncEnumerable.Empty<Abblix.Jwt.JsonWebKey>());
        var issuer = new ProfiledJwtIssuer(Get<Abblix.Jwt.IJsonWebTokenCreator>(), Get<Abblix.Jwt.EncryptionAlgorithmsProvider>());
        var clientJwtFormatter = new ClientJwtFormatter(
            NullLogger<ClientJwtFormatter>.Instance,
            issuer, new ClientEncryptionKeyResolver(
                issuer, clientKeys.Object, TimeProvider.System, Get<Abblix.Jwt.EncryptionAlgorithmsProvider>()), serviceKeys.Object);
        var formatter = new UserInfoResponseFormatter(TimeProvider.System, clientJwtFormatter, tenantAccessor, new FapiInteractionIdResolver(NullLogger<FapiInteractionIdResolver>.Instance));
        Result<UserInfoFoundResponse, OidcError> found = new UserInfoFoundResponse(
            new System.Text.Json.Nodes.JsonObject { [Abblix.Jwt.IanaClaimTypes.Sub] = "user-1" },
            client,
            tenant.Issuer.OriginalString);

        var response = await HttpResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), found));

        Assert.StartsWith(MediaTypes.Jwt, response.Headers.ContentType.ToString());
        var jwt = response.Body;

        var header = System.Text.Json.Nodes.JsonNode.Parse(
            System.Buffers.Text.Base64Url.DecodeFromChars(jwt.Split('.')[0]))!.AsObject();
        Assert.False(header.ContainsKey(Abblix.Jwt.JwtClaimTypes.ContentType));

        var opened = await Get<Abblix.Jwt.IJsonWebTokenValidator>().ValidateAsync(jwt, new Abblix.Jwt.ValidationParameters
        {
            TokenTypes = Abblix.Jwt.TokenTypePolicy.CheckedByCaller,
            Options = default,
            ResolveTokenDecryptionKeys = _ => clientKey.ToAsync(),
        });
        Assert.True(opened.TryGetSuccess(out var token));
        Assert.Equal("user-1", token.Payload.Subject);
    }
}
