// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A JWT the server cannot sign for the client - here because no signing key of the tenant, which holds only an RSA key,
/// produces the ES256 the client registered - is not issued, and the endpoint answers it in its own protocol rather than
/// with a server error: the token endpoint with unauthorized_client (RFC 6749 section 5.2), the UserInfo endpoint with
/// invalid_token (RFC 6750 section 3.1, as OpenID Connect Core 1.0 section 5.3.3 has it answer).
/// </summary>
public sealed class UnproducibleClientJwtTests
{
    private const string Acme = SignedInTenantsHost.Acme;
    private const string ClientSecret = "client-secret";
    private const string TokenPath = "/connect/token";
    private const string UserInfoPath = "/connect/userinfo";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri the client registers; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private static Task<SignedInTenantsHost> StartAsync(Action<ClientInfo> configure)
        => SignedInTenantsHost.StartAsync(_ =>
        {
            var client = new ClientInfo(SignedInTenantsHost.ClientId)
            {
                ClientSecrets =
                [
                    new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
                ],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                RedirectUris = [new Uri(RedirectUri)],
                PkceRequired = true,
            };
            configure(client);
            return client;
        });

    private static Task<HttpResponseMessage> RedeemAsync(SignedInTenantsHost host, string code)
        => host.Http.PostAsync(
            Acme + TokenPath,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = code,
                [TokenRequest.Parameters.RedirectUri] = RedirectUri,
                [TokenRequest.Parameters.CodeVerifier] = SignedInTenantsHost.CodeVerifier,
                [ClientRequest.Parameters.ClientId] = SignedInTenantsHost.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    /// <summary>
    /// An ID token no tenant key can sign is refused with unauthorized_client, and the code it was asked for stays
    /// spent: it was claimed before the tokens were issued, so a second redemption is invalid_grant.
    /// </summary>
    [Fact]
    public async Task AnIdTokenNoTenantKeySigns_IsRefusedWithUnauthorizedClient()
    {
        await using var host = await StartAsync(client =>
            client.IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.ES256);
        var code = await host.CodeAtAsync(Acme, RedirectUri);

        var refused = await RedeemAsync(host, code);

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(
            ErrorCodes.UnauthorizedClient,
            (await ReadJsonAsync(refused))[ErrorResponse.Parameters.Error]?.GetValue<string>());

        var again = await RedeemAsync(host, code);
        Assert.Equal(
            ErrorCodes.InvalidGrant,
            (await ReadJsonAsync(again))[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// A UserInfo response the client registered signed with an algorithm no tenant key produces is refused with
    /// invalid_token, rather than sent unsigned or answered with a server error.
    /// </summary>
    [Fact]
    public async Task AUserInfoResponseNoTenantKeySigns_IsRefusedWithInvalidToken()
    {
        await using var host = await StartAsync(client =>
            client.UserInfoSignedResponseAlgorithm = SigningAlgorithms.ES256);
        var tokens = await ReadJsonAsync(await RedeemAsync(host, await host.CodeAtAsync(Acme, RedirectUri)));
        var accessToken = tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        using var request = new HttpRequestMessage(HttpMethod.Get, Acme + UserInfoPath);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        var response = await host.Http.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(
            ErrorCodes.InvalidToken,
            response.Headers.WwwAuthenticate.ToString(),
            StringComparison.Ordinal);
    }
}
