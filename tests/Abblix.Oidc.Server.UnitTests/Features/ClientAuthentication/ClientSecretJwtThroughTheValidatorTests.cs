// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Validation;
using System;
using System.Text;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;
using JsonWebToken = Abblix.Jwt.JsonWebToken;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// client_secret_jwt through the JWT validator the server registers rather than a double of it. That
/// validator resolves the signing keys before it checks the issuer, and resolving the keys is where the
/// client is looked up, so only the real one shows which tenant that lookup is made at.
/// </summary>
public class ClientSecretJwtThroughTheValidatorTests
{
    private const string ClientId = "client-a";
    private const string Secret = "0123456789abcdef0123456789abcdef0123456789";
    private const string TokenUri = "https://auth.example.com/token";

    private static readonly TenantDefinition Acme = new() { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") };
    private static readonly TenantDefinition Globex = new() { Id = "globex", Issuer = new Uri("https://auth.example.com/globex") };

    /// <summary>
    /// A signed assertion of a client registered only at one tenant authenticates it there and is refused at
    /// another tenant.
    /// </summary>
    [Fact]
    public async Task AClientRegisteredOnlyAtAnotherTenant_IsRefused()
    {
        await using var jwt = JsonWebTokenServices();
        var authenticator = Authenticator(jwt);

        // Each assertion names the issuer of the tenant it is presented at, so the client lookup alone
        // decides the second one
        Assert.NotNull(await authenticator.TryAuthenticateClientAsync(Globex, await RequestAsync(jwt, [Globex.Issuer.OriginalString])));
        Assert.Null(await authenticator.TryAuthenticateClientAsync(Acme, await RequestAsync(jwt, [Acme.Issuer.OriginalString])));
    }

    /// <summary>
    /// RFC 10070 section 4: "the token endpoint URL of the authorization server MUST NOT be used as an audience
    /// value", and an assertion without the issuer as its sole audience is refused, also when it carries no
    /// audience at all. Driven through the real validator, since the authenticator hands it the audience
    /// requirement and judges the value itself.
    /// </summary>
    [Theory]
    [InlineData(TokenUri)]
    [InlineData(null)]
    public async Task AnAssertionNotNamingTheIssuerAlone_IsRefused(string? audience)
    {
        await using var jwt = JsonWebTokenServices();
        var authenticator = Authenticator(jwt);

        string[] audiences = audience is null ? [] : [audience];
        Assert.Null(await authenticator.TryAuthenticateClientAsync(Globex, await RequestAsync(jwt, audiences)));
    }

    private static ServiceProvider JsonWebTokenServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    private static ClientSecretJwtAuthenticator Authenticator(IServiceProvider jwt)
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = Secret }],
        };
        var clients = new Mock<IClientInfoProvider>();
        clients
            .Setup(p => p.TryFindClientAsync(It.IsAny<TenantDefinition>(), ClientId))
            .ReturnsAsync((TenantDefinition tenant, string _) => tenant.Id == Globex.Id ? client : null);
        var replayCache = new Mock<IReplayCache>();
        replayCache
            .Setup(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        return new ClientSecretJwtAuthenticator(
            NullLogger<ClientSecretJwtAuthenticator>.Instance,
            new ProfiledJwtValidator(jwt.GetRequiredService<IJsonWebTokenValidator>()),
            clients.Object,
            TimeProvider.System,
            replayCache.Object,
            new ServiceCollection().BuildServiceProvider());
    }

    private static async Task<ClientRequest> RequestAsync(IServiceProvider jwt, string[] audiences)
    {
        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.HS256 },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = ClientId,
                Subject = ClientId,
                Audiences = audiences,
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(1),
            },
        };
        var key = new OctetJsonWebKey { Algorithm = SigningAlgorithms.HS256, KeyValue = Encoding.UTF8.GetBytes(Secret) };
        var assertion = await jwt.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key);
        return new ClientRequest { ClientAssertionType = ClientAssertionTypes.JwtBearer, ClientAssertion = assertion };
    }
}
