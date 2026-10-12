// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A relying party requires the issuer of discovery to "exactly match the value of the iss (issuer) Claim" (OpenID
/// Connect Core 1.0 section 3.1.3.7), so the issuer is written as it is configured. The server here is configured with
/// a bare host, which reading the issuer as a normalized URI would write with a trailing slash.
/// </summary>
public class IssuerAsWrittenTests(TestFactory factory) : TestBase(factory)
{
    private const string TokenEndpointIdToken = "id_token";
    private const string TokenEndpointAccessToken = "access_token";

    [Fact]
    public async Task TheIssuer_IsWrittenAsGiven_InDiscoveryAndInEveryToken()
    {
        var client = CreateClient();
        const string expected = TestConstants.Issuer;

        var document = JsonNode.Parse(await client.GetStringAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken))!;
        Assert.Equal(expected, document[ConfigurationResponse.Parameters.Issuer]!.GetValue<string>());

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, await FetchDiscoveryAsync(client));
        foreach (var name in new[] { TokenEndpointIdToken, TokenEndpointAccessToken })
        {
            var payload = DecodeJwtPayload(tokens[name]!.GetValue<string>());
            Assert.Equal(expected, payload[JwtClaimTypes.Issuer]!.GetValue<string>());
        }
    }
}
