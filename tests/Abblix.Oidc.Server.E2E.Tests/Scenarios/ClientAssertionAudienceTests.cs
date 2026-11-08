// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 10070 section 4, case B, as a client meets it at the token endpoint: a client authentication assertion
/// carries the server's issuer identifier as its sole audience, and one naming the token endpoint URL - which
/// that section says "MUST NOT be used as an audience value" - or the issuer beside another recipient is
/// refused as from a client that cannot authenticate.
/// </summary>
public class ClientAssertionAudienceTests(TestFactory factory) : TestBase(factory)
{
    private static readonly IServiceProvider JwtServices = BuildJwtServices();

    private static ServiceProvider BuildJwtServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task AnAssertionNamingTheIssuerAlone_IsIssuedAToken()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, await FormAsync([discovery.Issuer.OriginalString]));

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(response.IsSuccessStatusCode, body.ToJsonString());
        Assert.NotNull(body[TokenResponse.Parameters.AccessToken]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnAssertionNotNamingTheIssuerAlone_IsRefused(bool issuerBesideTheTokenEndpoint)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var tokenEndpoint = discovery.TokenEndpoint.OriginalString;
        string[] audiences = issuerBesideTheTokenEndpoint
            ? [discovery.Issuer.OriginalString, tokenEndpoint]
            : [tokenEndpoint];

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, await FormAsync(audiences));

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidClient, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    private static async Task<Dictionary<string, string>> FormAsync(string[] audiences)
    {
        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.HS256, Type = JsonWebTokenTypes.ClientAuthentication },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = TestConstants.ClientSecretJwtClientId,
                Subject = TestConstants.ClientSecretJwtClientId,
                Audiences = audiences,
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(1),
            },
        };
        var key = new OctetJsonWebKey
        {
            Algorithm = SigningAlgorithms.HS256,
            KeyValue = Encoding.UTF8.GetBytes(TestConstants.ClientSecretJwtSecret),
        };

        return new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
            [ClientRequest.Parameters.ClientAssertion] =
                await JwtServices.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key),
        };
    }
}
