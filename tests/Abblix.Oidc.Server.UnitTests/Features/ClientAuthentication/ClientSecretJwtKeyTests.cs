// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// The keys a client_secret_jwt assertion is verified with: each derived from one of the client's secrets, read from
/// its value or decrypted from the copy a registered client keeps, for the HS algorithms its length keys.
/// </summary>
public class ClientSecretJwtKeyTests
{
    private const string ClientId = "client-a";
    private const string ShortSecret = "0123456789abcdef0123456789abcdef";
    private const string LongSecret = ShortSecret + ShortSecret;

    private static readonly TenantDefinition Tenant = new() { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") };

    private static readonly byte[] Encrypted = [1, 2, 3];

    /// <summary>
    /// RFC 7518 section 3.2: "A key of the same size as the hash output (for instance, 256 bits for "HS256") or larger
    /// MUST be used with this algorithm". A secret of 32 octets keys HS256 alone; one of 64 keys all three.
    /// </summary>
    [Theory]
    [InlineData(ShortSecret, new[] { SigningAlgorithms.HS256 })]
    [InlineData(LongSecret, new[] { SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512 })]
    public async Task ASecretKeysTheAlgorithmsItsLengthAllows(string secret, string[] algorithms)
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = secret }],
        };
        var keys = new ClientSigningKeys(Mock.Of<IClientKeysProvider>(), Mock.Of<IClientSecretEncryptor>(), TimeProvider.System);

        var derived = await keys.FromSecret(Tenant, client).Select(key => key.Algorithm).ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.Equal(algorithms, derived);
    }

    /// <summary>
    /// An assertion signed with the client's secret under an algorithm its length keys authenticates the client.
    /// </summary>
    [Theory]
    [InlineData(ShortSecret, SigningAlgorithms.HS256, true)]
    [InlineData(LongSecret, SigningAlgorithms.HS384, true)]
    [InlineData(LongSecret, SigningAlgorithms.HS512, true)]
    public async Task AnAssertionIsVerifiedWithItsSecret(string secret, string algorithm, bool accepted)
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = secret }],
        };

        Assert.Equal(accepted, await AuthenticatesAsync(client, secret, algorithm, Mock.Of<IClientSecretEncryptor>()));
    }

    /// <summary>
    /// A client registered dynamically keeps its secret encrypted alone, and its assertion is verified with the
    /// secret decrypted; once the tenant's key no longer opens it, the client is refused.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ARegisteredClientIsVerifiedWithItsDecryptedSecret(bool decrypts)
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { EncryptedValue = Encrypted }],
        };
        var encryptor = new Mock<IClientSecretEncryptor>();
        encryptor
            .Setup(e => e.Decrypt(It.Is<TenantDefinition>(t => t.Id == Tenant.Id), ClientId, Encrypted))
            .Returns(decrypts ? LongSecret : null);

        Assert.Equal(decrypts, await AuthenticatesAsync(client, LongSecret, SigningAlgorithms.HS256, encryptor.Object));
    }

    /// <summary>
    /// Only a client_secret_jwt client has its secret decrypted: one registered for another method is verified
    /// against the hash, so its encrypted copy keys no assertion.
    /// </summary>
    [Fact]
    public async Task AClientOfAnotherMethodHasNoSecretDecrypted()
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            ClientSecrets = [new ClientSecret { EncryptedValue = Encrypted }],
        };
        var encryptor = new Mock<IClientSecretEncryptor>(MockBehavior.Strict);

        Assert.False(await AuthenticatesAsync(client, LongSecret, SigningAlgorithms.HS256, encryptor.Object));
    }

    private static async Task<bool> AuthenticatesAsync(
        ClientInfo client, string signingSecret, string algorithm, IClientSecretEncryptor encryptor)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        await using var jwt = services.BuildServiceProvider();

        var replayCache = new Mock<IReplayCache>();
        replayCache
            .Setup(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);
        var authenticator = new ClientSecretJwtAuthenticator(
            NullLogger<ClientSecretJwtAuthenticator>.Instance,
            TimeProvider.System,
            replayCache.Object,
            ClientSecretJwtServices.With(
                new ProfiledJwtValidator(jwt.GetRequiredService<IJsonWebTokenValidator>()),
                TimeProvider.System,
                encryptor: encryptor),
            DefaultOidcOptions.Monitor());

        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(p => p.FindClientAsync(It.IsAny<TenantDefinition>(), ClientId)).ReturnsAsync(client);

        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = algorithm },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = ClientId,
                Subject = ClientId,
                Audiences = [Tenant.Issuer.OriginalString],
                IssuedAt = now,
                ExpiresAt = now.AddMinutes(1),
            },
        };
        var key = new OctetJsonWebKey { Algorithm = algorithm, KeyValue = Encoding.UTF8.GetBytes(signingSecret) };
        var assertion = await jwt.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key);

        var result = await authenticator.TryAuthenticateClientAsync(
            Tenant,
            new ClientRequest { ClientAssertionType = ClientAssertionTypes.JwtBearer, ClientAssertion = assertion },
            clients.Object);
        return result.TryGetSuccess(out _);
    }
}
