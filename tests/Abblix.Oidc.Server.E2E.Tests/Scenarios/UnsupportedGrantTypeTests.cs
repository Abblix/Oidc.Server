// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.4: unsupported_grant_type is "The authorization grant type is not
/// supported by the authorization server", unauthorized_client "The authenticated client is not authorized to use this
/// authorization grant type". Through the host's own composition of the grant handlers, a type no handler serves is
/// answered as unsupported for a client not allowed it, and a type the server serves but the client may not use as
/// unauthorized.
/// </summary>
public class UnsupportedGrantTypeTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData("urn:example:unknown", ErrorCodes.UnsupportedGrantType)]
    [InlineData("Authorization_Code", ErrorCodes.UnsupportedGrantType)]
    [InlineData(GrantTypes.ClientCredentials, ErrorCodes.UnauthorizedClient)]
    public async Task AGrantTypeTheClientMayNotUse_IsAnsweredForWhetherTheServerSupportsIt(
        string grantType, string expectedError)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = grantType,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(expectedError, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }
}
