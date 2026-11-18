// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Basic credentials that are not base64 are a malformed client authentication, which RFC 6749 section 5.2 answers
/// with invalid_client, not a failure of the server.
/// </summary>
public class MalformedBasicCredentialsTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task CredentialsThatAreNotBase64_AreAnsweredWithInvalidClient()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Basic, "not*base64!");
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
        });

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidClient, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }
}
