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
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public class ClientUpdateAuthenticationMethodTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// RFC 7592 section 2.2 replaces the metadata, not the secret, and the update issues none: an update moving a client
    /// to a method its stored secret cannot serve is refused with invalid_client_metadata ("the authorization server
    /// responds with an error as described in [RFC7591]"). A public client holds no secret at all. A registration stores
    /// the secret's hash and its encrypted copy, so a client moves between client_secret_basic and client_secret_jwt and
    /// authenticates with its secret either way, and a client_secret_jwt client updating its other metadata keeps
    /// authenticating.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.None, ClientAuthenticationMethods.ClientSecretPost, false)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, ClientAuthenticationMethods.ClientSecretJwt, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt, ClientAuthenticationMethods.ClientSecretJwt, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt, ClientAuthenticationMethods.ClientSecretBasic, true)]
    public async Task An_update_moves_a_client_only_to_a_method_its_secret_serves(
        string registeredMethod, string updatedMethod, bool served)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = new JsonObject
        {
            [RequestMembers.ClientName] = $"method-{registeredMethod}-{updatedMethod}",
            [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials),
            [RequestMembers.ResponseTypes] = new JsonArray(),
            [RequestMembers.TokenEndpointAuthMethod] = registeredMethod,
        };

        // A client authenticating with none may not hold the client credentials grant (RFC 6749 section 4.4), so the
        // public one is registered for the authorization code grant instead
        if (registeredMethod == ClientAuthenticationMethods.None)
        {
            metadata[RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode);
            metadata[RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code);
            metadata[RequestMembers.RedirectUris] = new JsonArray("https://client.example.com/callback");
        }

        var registered = await RegisterClientAsync(client, discovery, metadata);
        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();

        metadata[RequestMembers.ClientId] = clientId;
        metadata[RequestMembers.TokenEndpointAuthMethod] = updatedMethod;
        using var update = new HttpRequestMessage(
            HttpMethod.Put, registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>())
        {
            Content = JsonContent.Create(metadata),
        };
        update.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        using var updated = await client.SendAsync(update, TestContext.Current.CancellationToken);
        var updatedBody = await ReadJsonAsync(updated);

        if (!served)
        {
            Assert.True(updated.StatusCode == HttpStatusCode.BadRequest, $"{(int)updated.StatusCode}");
            Assert.Equal(
                ErrorCodes.InvalidClientMetadata,
                updatedBody[ErrorResponse.Parameters.Error]!.GetValue<string>());
            return;
        }

        Assert.True(
            updated.StatusCode == HttpStatusCode.OK,
            $"{(int)updated.StatusCode}: {updatedBody[ErrorResponse.Parameters.ErrorDescription]}");

        var secret = registered[ResponseMembers.ClientSecret]!.GetValue<string>();
        var form = new Dictionary<string, string> { [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials };
        if (updatedMethod == ClientAuthenticationMethods.ClientSecretJwt)
        {
            form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
            form[ClientRequest.Parameters.ClientAssertion] = await ClientSecretJwtAssertion.IssueWithSecretAsync(
                clientId, secret, discovery.Issuer.OriginalString);
        }

        using var token = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (updatedMethod != ClientAuthenticationMethods.ClientSecretJwt)
        {
            token.Headers.Authorization = new AuthenticationHeaderValue(
                TokenTypes.Basic, Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{secret}")));
        }
        using var tokenResponse = await client.SendAsync(token, TestContext.Current.CancellationToken);

        // The token response carries the access token, so only the error is quoted
        Assert.True(
            tokenResponse.StatusCode == HttpStatusCode.OK,
            $"{(int)tokenResponse.StatusCode}: {(await ReadJsonAsync(tokenResponse))[ErrorResponse.Parameters.Error]}");
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
}
