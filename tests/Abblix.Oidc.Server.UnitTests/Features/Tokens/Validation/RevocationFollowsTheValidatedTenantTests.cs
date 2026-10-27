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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// A token of this server is validated for the tenant its caller hands over, and what is recorded about it is read
/// at that tenant too, whichever tenant the request happens to be served at.
/// </summary>
public class RevocationFollowsTheValidatedTenantTests
{
    private const string JwtId = "jti-1";
    private const string GrantId = "grant-1";

    // The tenant every token here is validated for is the one the run serves, so the license counts it once
    private static readonly TenantDefinition Validated = SingleIssuer.Tenant;
    private static readonly TenantDefinition Other = new() { Id = "other", Issuer = new Uri("https://auth.example.com/other") };

    /// <summary>
    /// What may be recorded about a token of this server, each refusing it on its own.
    /// </summary>
    public enum Recorded
    {
        TokenRevoked,
        TokenUsed,
        GrantRevoked,
        CutOff,
    }

    /// <summary>
    /// A token recorded as refused at the tenant it is validated for is refused, also while the request is served at
    /// another tenant, with no tenant scope entered by the validator.
    /// </summary>
    [Theory]
    [InlineData(Recorded.TokenRevoked, true)]
    [InlineData(Recorded.TokenRevoked, false)]
    [InlineData(Recorded.TokenUsed, true)]
    [InlineData(Recorded.TokenUsed, false)]
    [InlineData(Recorded.GrantRevoked, true)]
    [InlineData(Recorded.GrantRevoked, false)]
    [InlineData(Recorded.CutOff, true)]
    [InlineData(Recorded.CutOff, false)]
    public async Task ATokenRecordedAtItsTenant_IsRefused(Recorded recorded, bool servedAtItsTenant)
    {
        var result = await ValidateAsync(recordedAt: Validated, recorded, servedAt: servedAtItsTenant ? Validated : Other);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(RefusalOf(recorded), error.Error);
    }

    /// <summary>
    /// A token recorded as refused only at the tenant the request is served at, not at the one it is validated for,
    /// is accepted.
    /// </summary>
    [Theory]
    [InlineData(Recorded.TokenRevoked)]
    [InlineData(Recorded.TokenUsed)]
    [InlineData(Recorded.GrantRevoked)]
    [InlineData(Recorded.CutOff)]
    public async Task ATokenRecordedOnlyAtTheServedTenant_IsAccepted(Recorded recorded)
    {
        var result = await ValidateAsync(recordedAt: Other, recorded, servedAt: Other);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The refusal what is recorded makes, so a refusal for any other reason does not pass for it.
    /// </summary>
    private static JwtError RefusalOf(Recorded recorded) => recorded switch
    {
        Recorded.TokenRevoked or Recorded.GrantRevoked or Recorded.CutOff => JwtError.TokenRevoked,
        Recorded.TokenUsed => JwtError.TokenAlreadyUsed,
        _ => throw new ArgumentOutOfRangeException(nameof(recorded), recorded, "A record without an expected refusal."),
    };

    private static async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        TenantDefinition recordedAt,
        Recorded recorded,
        TenantDefinition servedAt)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                JwtId = JwtId,
                GrantId = GrantId,
                Issuer = Validated.Issuer.OriginalString,
                Subject = "alice",
                ExpiresAt = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero),
            },
        };

        var inner = new Mock<IJsonWebTokenValidator>();
        inner.Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(
                async (_, parameters) =>
                {
                    if (parameters.ValidateIssuer != null)
                        await parameters.ValidateIssuer(token.Payload.Issuer!);

                    return token;
                }));

        var registry = new Mock<ITokenRegistry>();
        registry.Setup(r => r.GetStatusAsync(It.IsAny<TenantDefinition>(), It.IsAny<string>()))
            .ReturnsAsync((TenantDefinition tenant, string id) => StatusOf(tenant, id));

        var cutoffs = new Mock<IRevocationCutoffChecker>();
        cutoffs.Setup(c => c.CheckAsync(It.IsAny<TenantDefinition>(), It.IsAny<JsonWebTokenPayload>()))
            .ReturnsAsync((TenantDefinition tenant, JsonWebTokenPayload _) =>
                recorded == Recorded.CutOff && tenant.Id == recordedAt.Id
                    ? new JwtValidationError(JwtError.TokenRevoked, "Cut off")
                    : null);

        var validator = new AuthServiceJwtValidator(
            inner.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<IAuthServiceKeysProvider>(),
            new TokenStatusCheck(
                registry.Object,
                cutoffs.Object,
                new GrantRevocation(registry.Object, Mock.Of<IClientInfoProvider>())));

        // The request served at a tenant, as tenant resolution leaves it, around the validation
        using var request = TenantScope.Enter(servedAt);
        return await validator.ValidateAsync(Validated, "jwt", TokenTypePolicy.CheckedByCaller);

        JsonWebTokenStatus StatusOf(TenantDefinition tenant, string id)
        {
            if (tenant.Id != recordedAt.Id)
                return JsonWebTokenStatus.Unknown;

            return (recorded, id) switch
            {
                (Recorded.TokenRevoked, JwtId) => JsonWebTokenStatus.Revoked,
                (Recorded.TokenUsed, JwtId) => JsonWebTokenStatus.Used,
                (Recorded.GrantRevoked, GrantId) => JsonWebTokenStatus.Revoked,
                _ => JsonWebTokenStatus.Unknown,
            };
        }
    }
}
