// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the service-token encryption model: when a server encryption key is configured, the
/// tokens the server issues for itself are encrypted to it by default (as in prior versions), and encryption
/// can be turned off per token type. The default is opaque-first - an encrypted access token is consumed by
/// the server's own UserInfo endpoint - and a host keeps the access token readable by external resource
/// servers by disabling its encryption. These settings are enabled on an isolated host so the shared default
/// suite is untouched.
/// </summary>
public class ServiceTokenEncryptionTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// With an encryption key configured and default settings, the access token issued through the real flow
    /// is an encrypted JWE (five segments), reproducing the prior-version behavior, and the server's own
    /// UserInfo endpoint reads it back - the access token is opaque to third parties but consumed first-party.
    /// </summary>
    [Fact]
    public async Task EncryptionKeyConfigured_AccessTokenEncryptedByDefault_AndConsumedByOwnUserInfo()
    {
        await using var host = CreateHost(_ => { });
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        Assert.Equal(5, SegmentCount(accessToken));

        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.True(
            response.IsSuccessStatusCode,
            $"/userinfo rejected the encrypted access token: {(int)response.StatusCode} " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Encryption is turned off per token type: disabling the access token's encryption leaves it a signed JWS
    /// (three segments) even though a key is configured, while the refresh token stays encrypted (five
    /// segments). The encrypted refresh token still round-trips - the server decrypts and validates its own
    /// JWE on the refresh grant.
    /// </summary>
    [Fact]
    public async Task AccessTokenEncryptionDisabled_AccessTokenSignedOnly_RefreshStillEncrypted()
    {
        await using var host = CreateHost(options => options.ServiceTokens.AccessToken.Encrypt = false);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        Assert.Equal(3, SegmentCount(accessToken));
        Assert.Equal(5, SegmentCount(refreshToken));

        var refreshed = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        Assert.NotNull(refreshed[UserInfoRequest.Parameters.AccessToken]);
    }

    /// <summary>
    /// Builds an isolated host with a service encryption key configured, plus any per-test option tweak, so the
    /// shared default host (and the rest of the suite) stays untouched. The key is generated once and captured,
    /// so the same key pair encrypts and later decrypts within the host.
    /// </summary>
    private WebApplicationFactory<Program> CreateHost(Action<OidcOptions> configure)
    {
        var encryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        return Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options =>
                        {
                            options.EncryptionKeys = [encryptionKey];
                            configure(options);
                        }))));
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    private static int SegmentCount(string jwt) => jwt.Split('.').Length;

    /// <summary>
    /// A host that requires encryption while no key can serve it does not come up. This is the end-to-end half
    /// of the refusal: the unit test proves the validator returns a failure, and only a real host proves the
    /// failure is raised rather than collected and ignored.
    /// </summary>
    /// <remarks>
    /// It does not prove that the refusal comes from <c>ValidateOnStart</c>. Measured by mutation: removing
    /// that call leaves this test green, because something in the composition already reads
    /// <c>IOptions&lt;OidcOptions&gt;.Value</c> while the host starts. The call is kept as a stated contract
    /// rather than a behaviour this test can observe.
    /// </remarks>
    [Fact]
    public void StartupIsRefusedWhenEncryptionIsRequiredWithoutAnyKey()
    {
        using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options =>
                        {
                            options.EncryptionKeys = [];
                            options.ServiceTokens.AccessToken.Encrypt = true;
                        }))));

        var exception = Assert.Throws<OptionsValidationException>(() => CreateClientFor(host));

        Assert.Contains(exception.Failures, f => f.Contains("AccessToken.Encrypt is true"));
    }
}
