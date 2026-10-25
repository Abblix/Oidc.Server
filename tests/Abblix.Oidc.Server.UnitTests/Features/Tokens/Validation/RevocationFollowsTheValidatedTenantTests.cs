// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// A token is validated for the tenant its caller hands over, and what is recorded about it, its status, is
/// read at that tenant too, whichever tenant the request happens to be served at.
/// </summary>
public class RevocationFollowsTheValidatedTenantTests
{
    private const string JwtId = "jti-1";
    private const string ClientId = "client-1";
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    // The tenant every token here is validated for is the one the run serves, so the license counts it once
    private static readonly TenantDefinition Validated = SingleIssuer.Tenant;
    private static readonly TenantDefinition Other = new() { Id = "other", Issuer = new Uri("https://auth.example.com/other") };

    /// <summary>
    /// Answers as the server's own accessor does: the tenant of a scope entered, otherwise the request's.
    /// </summary>
    private sealed class ServedAt(TenantDefinition request) : ITenantAccessor
    {
        public TenantContext? Current => TenantScope.Current ?? new TenantContext { Tenant = request };
    }

    /// <summary>
    /// The token status decorator over a stub validator answering <paramref name="token"/>, with the token revoked
    /// at the validated tenant alone.
    /// </summary>
    private static IJsonWebTokenValidator RevokedAtTheValidatedTenant(JsonWebToken token, TenantDefinition servedAt)
    {
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
            .ReturnsAsync((TenantDefinition tenant, string _) =>
                tenant.Id == Validated.Id ? JsonWebTokenStatus.Revoked : JsonWebTokenStatus.Unknown);

        var cutoffs = new Mock<IRevocationCutoffChecker>();
        cutoffs.Setup(c => c.CheckAsync(It.IsAny<TenantDefinition>(), It.IsAny<JsonWebTokenPayload>()))
            .ReturnsAsync((JwtValidationError?)null);

        return new TokenStatusValidatorDecorator(
            registry.Object,
            cutoffs.Object,
            new GrantRevocation(registry.Object, Mock.Of<IClientInfoProvider>()),
            inner.Object,
            new ServedAt(servedAt));
    }

    /// <summary>
    /// A token this server issued at a tenant and revoked there is refused when validated for that tenant, also
    /// while the request is served at another.
    /// </summary>
    [Theory]
    [InlineData(TestIssuer.TenantId)]
    [InlineData("other")]
    public async Task ATokenOfTheServerRevokedAtItsTenant_IsRefused(string servedAt)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { JwtId = JwtId, Issuer = Validated.Issuer.OriginalString, Subject = "alice" },
        };
        var validator = new AuthServiceJwtValidator(
            RevokedAtTheValidatedTenant(token, servedAt == Validated.Id ? Validated : Other),
            SingleIssuer.LicensedCatalog,
            Mock.Of<IAuthServiceKeysProvider>());

        var result = await validator.ValidateAsync(Validated, "jwt", TokenTypePolicy.CheckedByCaller);

        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// A client's assertion revoked at the tenant it is validated for is refused there, also while the request is
    /// served at another tenant.
    /// </summary>
    [Theory]
    [InlineData(TestIssuer.TenantId)]
    [InlineData("other")]
    public async Task AClientsAssertionRevokedAtItsTenant_IsRefused(string servedAt)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                JwtId = JwtId,
                Issuer = ClientId,
                ClientId = ClientId,
                IssuedAt = Now,
                ExpiresAt = Now.AddHours(1),
                Audiences = [Validated.Issuer.OriginalString],
            },
        };
        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(p => p.TryFindClientAsync(It.IsAny<TenantDefinition>(), ClientId)).ReturnsAsync(new ClientInfo(ClientId));
        var requestInfo = new Mock<IRequestInfoProvider>();
        requestInfo.Setup(p => p.RequestUri).Returns(Validated.Issuer);
        var serviceKeys = new Mock<IAuthServiceKeysProvider>();
        serviceKeys.Setup(p => p.GetEncryptionKeys(It.IsAny<TenantDefinition>(), It.IsAny<bool>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        var validator = new ClientJwtValidator(
            NullLogger<ClientJwtValidator>.Instance,
            requestInfo.Object,
            RevokedAtTheValidatedTenant(token, servedAt == Validated.Id ? Validated : Other),
            clients.Object,
            new Mock<IClientKeysProvider>().Object,
            serviceKeys.Object,
            new FakeTimeProvider(Now));

        var result = await validator.ValidateAsync(Validated, "header.payload.signature", TokenTypePolicy.CheckedByCaller);

        Assert.True(result.TryGetFailure(out _));
    }
}
