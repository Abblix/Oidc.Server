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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.Features.DPoP;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;
using JsonWebToken = Abblix.Jwt.JsonWebToken;

namespace Abblix.Oidc.Server.UnitTests.Features.ReplayPrevention;

/// <summary>
/// The replay checks of DPoP proofs, client assertions and JWT bearer grants are decided by the add-if-absent of the
/// host's entity storage, so a storage whose add-if-absent holds across nodes makes them hold across nodes too.
/// </summary>
/// <remarks>
/// Driven through the server's registrations over a storage that refuses every read and plain write: a replay cache
/// that decided by reading first, or kept its reservations anywhere else, fails here.
/// </remarks>
public class ReplayChecksThroughEntityStorageTests
{
    private const string Prefix = "Abblix.Oidc.Server.Features.ReplayPrevention:";
    private const string ClientId = "client-a";
    private const string Secret = "0123456789abcdef0123456789abcdef0123456789";

    private static readonly TenantDefinition Tenant = new() { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") };

    private static readonly SecurityProfileRequirements Unprofiled =
        SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);

    private readonly AddIfAbsentOnlyStorage _storage = new();

    /// <summary>
    /// Of many callers reserving one identifier at once, exactly one hears that it is new, with the storage's
    /// add-if-absent the only operation that could decide between them.
    /// </summary>
    [Fact]
    public async Task ConcurrentReservationsOfOneIdentifier_HaveOneWinner()
    {
        await using var provider = Services().BuildServiceProvider();
        var replayCache = provider.GetRequiredService<IReplayCache>();
        var expiresAt = TimeProvider.System.GetUtcNow().AddMinutes(5);

        var answers = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(
            () => replayCache.TryReserveAsync("one-token", expiresAt, TestContext.Current.CancellationToken))));

        Assert.Single(answers, fresh => fresh);
        Assert.Equal([Prefix + "one-token"], _storage.Held);
    }

    /// <summary>
    /// A reservation given back is removed from the storage, so the same identifier reads as fresh again.
    /// </summary>
    [Fact]
    public async Task AReleasedReservation_IsFreshAgain()
    {
        await using var provider = Services().BuildServiceProvider();
        var replayCache = provider.GetRequiredService<IReplayCache>();
        var expiresAt = TimeProvider.System.GetUtcNow().AddMinutes(5);
        var ct = TestContext.Current.CancellationToken;

        Assert.True(await replayCache.TryReserveAsync("one-token", expiresAt, ct));
        await replayCache.ReleaseAsync("one-token", ct);

        Assert.Empty(_storage.Held);
        Assert.True(await replayCache.TryReserveAsync("one-token", expiresAt, ct));
    }

    [Fact]
    public async Task ADPoPProofPresentedTwice_IsRefusedByTheStorage()
    {
        var requestInfo = new Mock<IRequestInfoProvider>();
        requestInfo.SetupGet(p => p.RequestMethod).Returns("POST");
        requestInfo.SetupGet(p => p.RequestUri).Returns(new Uri("https://auth.example.com/token"));

        var services = Services();
        services.AddSingleton(requestInfo.Object);
        services.AddDPoP();
        services.AddSingleton<ProfiledJwtValidator>();
        await using var provider = services.BuildServiceProvider();
        var validator = provider.GetRequiredService<IProofValidator>();

        var builder = new DPoPProofBuilder(TimeProvider.System.GetUtcNow());
        var proof = builder.Build();
        var ct = TestContext.Current.CancellationToken;

        Assert.True((await validator.ValidateAsync(Unprofiled, proof, cancellationToken: ct)).TryGetSuccess(out _));
        Assert.True((await validator.ValidateAsync(Unprofiled, proof, cancellationToken: ct)).TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.ReplayDetected, error.Reason);
        Assert.Equal([Prefix + builder.Jti, Prefix + builder.Jti], _storage.Claimed);
    }

    [Fact]
    public async Task AClientAssertionPresentedTwice_IsRefusedByTheStorage()
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = Secret }],
        };
        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(p => p.TryFindClientAsync(Tenant, ClientId)).ReturnsAsync(client);

        var services = Services();
        services.AddSingleton<ProfiledJwtValidator>();
        await using var provider = services.BuildServiceProvider();
        var authenticator = ActivatorUtilities.CreateInstance<ClientSecretJwtAuthenticator>(provider, clients.Object);

        var jwtId = Guid.NewGuid().ToString("N");
        var request = await AssertionAsync(provider, jwtId);

        Assert.True((await authenticator.TryAuthenticateClientAsync(Tenant, request)).TryGetSuccess(out _));
        Assert.True((await authenticator.TryAuthenticateClientAsync(Tenant, request)).TryGetFailure(out _));
        Assert.Equal([Prefix + jwtId, Prefix + jwtId], _storage.Claimed);
    }

    [Fact]
    public async Task AJwtBearerAssertionPresentedTwice_IsRefusedByTheStorage()
    {
        var services = Services();
        services.AddJwtBearerGrant();
        await using var provider = services.BuildServiceProvider();
        var issuers = ActivatorUtilities.CreateInstance<JwtBearerIssuerProvider>(
            provider, new Mock<ISecureHttpFetcher>().Object);
        var expiresAt = TimeProvider.System.GetUtcNow().AddMinutes(5);

        Assert.False(await issuers.IsReplayedAsync("bearer-jti", expiresAt));
        Assert.True(await issuers.IsReplayedAsync("bearer-jti", expiresAt));
        Assert.Equal([Prefix + "bearer-jti", Prefix + "bearer-jti"], _storage.Claimed);
    }

    private ServiceCollection Services()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        services.Configure<OidcOptions>(_ => { });
        services.AddJsonWebTokens();
        services.AddKeyedSingleton<IEntityStorage>(TenantServiceKeys.Shared, _storage);
        services.AddReplayPrevention();
        return services;
    }

    private static async Task<ClientRequest> AssertionAsync(IServiceProvider provider, string jwtId)
    {
        var now = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.HS256 },
            Payload =
            {
                JwtId = jwtId,
                Issuer = ClientId,
                Subject = ClientId,
                Audiences = [Tenant.Issuer.OriginalString],
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(1),
            },
        };
        var key = new OctetJsonWebKey { Algorithm = SigningAlgorithms.HS256, KeyValue = Encoding.UTF8.GetBytes(Secret) };
        var assertion = await provider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key);
        return new ClientRequest { ClientAssertionType = ClientAssertionTypes.JwtBearer, ClientAssertion = assertion };
    }
}
