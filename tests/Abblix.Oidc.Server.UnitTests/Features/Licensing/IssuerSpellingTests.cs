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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// The issuer is written into a token, and counted by the license, as it is configured: its case, its explicit
/// default port and its lack of a trailing slash, which reading it as a normalized URI would each change.
/// </summary>
/// <remarks>
/// In the license collection, which runs alone and resets the checker around each test, since the checker counts
/// issuers process-wide and an issuer spelled apart from the assembly's one would count against every other test.
/// </remarks>
[Collection(nameof(LicenseEnforcementTests))]
public sealed class IssuerSpellingTests : IDisposable
{
    public IssuerSpellingTests() => TestLicense.InstallWithIssuerLimit(1);

    /// <summary>Leaves the assembly's license in place for everything that runs afterwards.</summary>
    public void Dispose() => TestLicense.ResetChecker();

    [Theory]
    [InlineData("https://Auth.Example.com:443", false)]
    [InlineData("http://Localhost:5000", true)]
    public async Task TheIssuer_IsWrittenIntoATokenAndCountedAsConfigured(string configured, bool allowHttp)
    {
        var options = Options.Create(new OidcOptions { Issuer = new Uri(configured), AllowHttpIssuer = allowHttp });
        Assert.False(new IssuerOptionsValidator().Validate(null, options.Value).Failed);

        var issuerProvider = Mock.Of<IIssuerProvider>(provider => provider.GetIssuer() == options.Value.Issuer);
        var formatter = new Mock<IAuthServiceJwtFormatter>(MockBehavior.Strict);
        JsonWebToken? issued = null;
        formatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => issued = jwt)
            .ReturnsAsync("token");

        var service = new AccessTokenService(
            issuerProvider,
            new FakeTimeProvider(),
            Mock.Of<ITokenIdGenerator>(generator => generator.GenerateTokenId() == "token-id"),
            formatter.Object,
            new SubjectTypeConverter(),
            options,
            SingleIssuer.SettingsOf(options),
            new AudienceKeyResolver(Mock.Of<IResourceManager>(), Mock.Of<IResourceKeysProvider>()));

        await service.CreateAccessTokenAsync(
            new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "local"),
            new AuthorizationContext("client", [Scopes.OpenId], null),
            new ClientInfo("client"),
            grantId: null,
            null);

        Assert.NotNull(issued);
        Assert.Equal(configured, issued.Payload.Issuer);

        // The license already counts the issuer as configured, so another spelling of it is a second issuer
        var refusal = Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(new Uri(configured).ToString(), SingleIssuer.SettingsOf(options)));
        Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
    }
}
