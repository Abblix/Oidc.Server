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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// The issuer discovery publishes and the audience every check accepts as naming the issuer are one value, taken from
/// <see cref="TenantIssuerNaming"/>: for an issuer written with its default port and in mixed case, so that its
/// normalized form differs from the written one, the request object's validator, the JWT bearer grant, a profile's
/// request object rule and the signed CIBA request rule each accept exactly the spellings the owner accepts.
/// </summary>
public class IssuerNamingIsOneAnswerTests
{
    private const string WrittenIssuer = "https://Auth.Example.com:443/tenants/acme";

    private static readonly TestIssuer Issuer = new() { Issuer = new Uri(WrittenIssuer) };

    /// <summary>
    /// The handler's response names the issuer in another spelling, so the document can carry the owner's only by
    /// taking it from the owner.
    /// </summary>
    [Fact]
    public async Task ThePublishedIssuer_IsTheOwnersSpelling()
    {
        var document = await PublishedTokenEndpointIsAcceptedTests.PublishedDocumentAsync(
            new Mock<IOidcEndpointResolver>().Object, Issuer, new Uri("https://auth.example.com/tenants/acme"));

        Assert.Equal(Issuer.ToTenant().IssuerAsWritten(), document.Issuer);
        Assert.Equal(WrittenIssuer, document.Issuer);
    }

    [Theory]
    [InlineData(WrittenIssuer, true)]
    [InlineData("https://auth.example.com/tenants/acme", false)]
    [InlineData("https://Auth.Example.com:443/tenants/acme/", false)]
    [InlineData("https://auth.example.com:443/tenants/acme", false)]
    [InlineData("https://Auth.Example.com:443/tenants/acme/connect/authorize", false)]
    public async Task EveryCheck_AcceptsWhatTheOwnerAccepts(string audience, bool named)
    {
        var tenant = Issuer.ToTenant();

        Assert.Equal(named, tenant.IssuerIsNamedBy(audience));
        var requestObjectAudienceCheck = await RequestObjectAudienceCheck(tenant);
        Assert.Equal(named, await requestObjectAudienceCheck([audience]));
        Assert.Equal(
            named,
            await new JwtBearerAudienceValidator(NullLogger.Instance, serviceProvider: null)
                .ValidateAsync(tenant, [audience]));
        Assert.Equal(
            named,
            RequestObjectProfileRules.WhyRefused(
                new SecurityProfileRequirements { RequireIssuerAudienceInRequestObject = true },
                SignedRequest(audience).Payload,
                tenant,
                TimeProvider.System.GetUtcNow()) is null);
        Assert.Equal(
            named,
            SignedAuthenticationRequestRules.WhyRefused(
                SignedRequest(audience), tenant, [SigningAlgorithms.PS256]) is null);
    }

    /// <summary>
    /// The audience check the request object's validator hands the JWT validator for <paramref name="tenant"/>.
    /// </summary>
    private static async Task<ValidationParameters.ValidateAudienceDelegate> RequestObjectAudienceCheck(
        TenantDefinition tenant)
    {
        ValidationParameters? captured = null;
        var jwtValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, p) => captured = p)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "not the subject of this test"));
        var requestInfo = new Mock<IRequestInfoProvider>();
        requestInfo.Setup(r => r.RequestUri).Returns(new Uri("https://request-host.example.com:8443/connect/authorize"));

        var validator = new ClientJwtValidator(
            NullLogger<ClientJwtValidator>.Instance,
            requestInfo.Object,
            new ProfiledJwtValidator(jwtValidator.Object),
            new Mock<IClientKeysProvider>(MockBehavior.Strict).Object,
            new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict).Object,
            TimeProvider.System, Mock.Of<Abblix.Oidc.Server.Features.ClientInformation.IClientSecretEncryptor>());

        await validator.ValidateAsync(tenant, null, new Mock<IClientInfoProvider>().Object, "a.b.c", TokenTypePolicy.CheckedByCaller, signingAlgorithms: null);
        return captured!.ValidateAudience!;
    }

    /// <summary>
    /// A signed authentication request carrying every claim CIBA Core 1.0 section 7.1.1 requires, addressed to
    /// <paramref name="audience"/>.
    /// </summary>
    private static JsonWebToken SignedRequest(string audience)
    {
        var now = TimeProvider.System.GetUtcNow();
        return new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.PS256 },
            Payload =
            {
                Issuer = "client",
                Audiences = [audience],
                JwtId = Guid.NewGuid().ToString("N"),
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
    }
}
