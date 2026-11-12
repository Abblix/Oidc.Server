// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// A token this server issued is read back by whichever node the next request reaches, and that node's clock may lag
/// the one that issued it. Its <c>nbf</c> and <c>iat</c> may therefore be a little ahead of the reading node's clock,
/// within <see cref="OidcOptions.ClockSkew"/>, while its <c>exp</c> is held to the reading clock as it is.
/// </summary>
public class IssuedTokenOnALaggingInstanceTests
{
    private static readonly DateTimeOffset IssuingNode = new(2026, 11, 12, 16, 38, 16, TimeSpan.Zero);

    // The tenant the server is built with, so the token is signed and read with the keys it declares
    private static readonly TenantDefinition Tenant = new()
    {
        Id = TestIssuer.TenantId,
        Issuer = TestConstants.DefaultIssuer,
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    // The node reading the token, whose clock lags the issuing node's by the given amount
    private static ServiceProvider ReadingNode(TimeSpan lag, Action<OidcOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(IssuingNode - lag));
        services.AddOidcCore(options =>
        {
            options.Tenants.Add(Tenant);
            configure?.Invoke(options);
        });
        return services.BuildServiceProvider();
    }

    private static async Task<Result<JsonWebToken, JwtValidationError>> IssueAndReadAsync(
        ServiceProvider provider,
        TimeSpan lifetime)
    {
        var tenant = Tenant;
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = JsonWebTokenTypes.AccessToken },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = tenant.Issuer.OriginalString,
                Audiences = [tenant.Issuer.OriginalString],
                Subject = "alice",
                IssuedAt = IssuingNode,
                NotBefore = IssuingNode,
                ExpiresAt = IssuingNode + lifetime,
            },
        };
        var options = provider.GetRequiredService<IOptions<OidcOptions>>().Value;
        var jwt = await provider.GetRequiredService<IAuthServiceJwtFormatter>()
            .FormatAsync(tenant, token, ServiceJwtEncryption.ForAccessToken(options));

        return await provider.GetRequiredService<IAuthServiceJwtValidator>()
            .ValidateAsync(tenant, jwt, TokenTypePolicy.Exactly(JsonWebTokenTypes.AccessToken));
    }

    [Fact]
    public async Task ATokenIssuedByANodeAhead_IsAccepted_WithinTheTolerance()
    {
        await using var provider = ReadingNode(TimeSpan.FromSeconds(2));

        var result = await IssueAndReadAsync(provider, TimeSpan.FromMinutes(5));

        Assert.True(result.TryGetSuccess(out _), result.TryGetFailure(out var error) ? error.ErrorDescription : null);
    }

    /// <summary>
    /// A token dated exactly as far ahead as the tolerance is still accepted, so the boundary belongs to it.
    /// </summary>
    [Fact]
    public async Task ATokenDatedExactlyTheToleranceAhead_IsAccepted()
    {
        await using var provider = ReadingNode(new OidcOptions().ClockSkew);

        var result = await IssueAndReadAsync(provider, TimeSpan.FromMinutes(5));

        Assert.True(result.TryGetSuccess(out _), result.TryGetFailure(out var error) ? error.ErrorDescription : null);
    }

    [Fact]
    public async Task ATokenDatedFurtherAheadThanTheTolerance_IsRefused()
    {
        await using var provider = ReadingNode(TimeSpan.FromSeconds(10));

        var result = await IssueAndReadAsync(provider, TimeSpan.FromMinutes(5));

        Assert.True(result.TryGetFailure(out _));
    }

    [Fact]
    public async Task AToleranceOfZero_RefusesATokenDatedAheadAtAll()
    {
        await using var provider = ReadingNode(
            TimeSpan.FromSeconds(1),
            options => options.ClockSkew = TimeSpan.Zero);

        var result = await IssueAndReadAsync(provider, TimeSpan.FromMinutes(5));

        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// The tolerance covers only a token dated ahead; it never keeps a token alive past the expiry its issuer set.
    /// </summary>
    [Fact]
    public async Task TheTolerance_DoesNotExtendTheExpiry()
    {
        // The reading node is ahead this time, by a second more than the token lives
        await using var provider = ReadingNode(TimeSpan.FromSeconds(-61));

        var result = await IssueAndReadAsync(provider, TimeSpan.FromMinutes(1));

        Assert.True(result.TryGetFailure(out _));
    }
}
