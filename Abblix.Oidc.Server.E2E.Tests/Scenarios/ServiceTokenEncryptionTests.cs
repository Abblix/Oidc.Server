// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof that service-token encryption is an explicit per-type opt-in, not an implicit global
/// trigger. Configuring <see cref="OidcOptions.EncryptionKeys"/> — as a host would for an inbound need such as
/// decrypting client-sent request objects — no longer encrypts the outbound access token: it stays a signed
/// JWS that external resource servers can read. Encryption is turned on per token type by its
/// <see cref="ServiceTokenOptions.Encryption"/> block, and the two types are controlled independently. These
/// settings are enabled on an isolated host so the shared default suite is untouched.
/// </summary>
public class ServiceTokenEncryptionTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// The plan's security regression: with an encryption key configured but no <c>AccessToken.Encryption</c>
    /// block, the access token issued through the real flow is a signed JWS (three segments), not a JWE
    /// (five). Under the previous implicit rule any configured encryption key encrypted it, breaking external
    /// resource servers that hold only the signing public key.
    /// </summary>
    [Fact]
    public async Task EncryptionKeysConfigured_WithoutAccessTokenEncryptionBlock_AccessTokenIsSignedJws()
    {
        using var host = CreateHost(_ => { });
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        Assert.Equal(3, SegmentCount(accessToken));
    }

    /// <summary>
    /// Per-type independence: turning on the refresh token's <c>Encryption</c> block encrypts the refresh
    /// token (a five-segment JWE) while the access token stays a signed JWS. The encrypted refresh token then
    /// round-trips: the server decrypts and validates its own JWE on the refresh grant, issuing a new access
    /// token.
    /// </summary>
    [Fact]
    public async Task RefreshTokenEncryptionBlock_EncryptsRefreshTokenButLeavesAccessTokenSigned()
    {
        using var host = CreateHost(options =>
            options.ServiceTokens.RefreshToken.Encryption = new JwtEncryptionSettings());
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
    /// shared default host (and the rest of the suite) stays on the signed-only defaults. The key is generated
    /// once and captured, so the same key pair encrypts and later decrypts within the host.
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
}
