// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 8414 §3 lets the Authorization Server Metadata be published under the oauth-authorization-server
/// well-known suffix in addition to openid-configuration. The MVC adapter serves the identical document at
/// both, so a client that queries only oauth-authorization-server still resolves the provider's metadata.
/// </summary>
public class OAuthMetadataEndpointTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Oauth_authorization_server_suffix_serves_the_same_metadata_as_openid_configuration()
    {
        var client = CreateClient();
        var token = TestContext.Current.CancellationToken;

        var oidc = JsonNode.Parse(
            await client.GetStringAsync("/.well-known/openid-configuration", token))!.AsObject();

        var response = await client.GetAsync("/.well-known/oauth-authorization-server", token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var oauth = JsonNode.Parse(await response.Content.ReadAsStringAsync(token))!.AsObject();
        Assert.Equal(
            oidc[ConfigurationResponse.Parameters.Issuer]!.GetValue<string>(),
            oauth[ConfigurationResponse.Parameters.Issuer]!.GetValue<string>());
        Assert.Equal(
            oidc[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>(),
            oauth[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>());
    }
}
