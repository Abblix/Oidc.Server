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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using System.Linq;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// The profile decides a tolerance and the JWT validator applies whatever it is handed, and each of
/// those has its own cases. Neither says the profile's answer TRAVELS from one to the other, which
/// is the seam a construction site sits on: removing the line that carries it leaves both halves
/// green, because a validator handed the library default refuses nothing these cases drive.
/// </summary>
public class ProfileClockSkewReachesValidationTests
{
    /// <summary>
    /// Captures the parameters a client-assertion authenticator hands the JWT validator, which is
    /// where the profile's answer has to appear if it reaches anything at all.
    /// </summary>
    private static async Task<ValidationParameters> CaptureParameters(ClientSecurityProfile profile)
    {
        ValidationParameters? captured = null;

        var tokenValidator = new Mock<IJsonWebTokenValidator>();
        tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, parameters) => captured = parameters)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "not the subject of this test"));

        var clientInfoProvider = new Mock<IClientInfoProvider>();
        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync((ClientInfo?)null);

        var authenticator = new ClientSecretJwtAuthenticator(
            NullLogger<ClientSecretJwtAuthenticator>.Instance,
            tokenValidator.Object,
            clientInfoProvider.Object,
            new Mock<IRequestInfoProvider>().Object,
            TimeProvider.System,
            new Mock<IReplayCache>().Object,
            new Mock<IIssuerProvider>().Object,
            Options.Create(new OidcOptions { DefaultSecurityProfile = profile }));

        await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = "header.payload.signature",
        });

        return captured.NotNull(nameof(captured));
    }

    /// <summary>
    /// The dynamic-registration path. A software statement is a JWT from a party this server trusts
    /// but does not run, so the profile's answer reaches it too - and, like every other site,
    /// through a line of its own that nothing else would miss.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2)]
    [InlineData(ClientSecurityProfile.None)]
    public async Task SoftwareStatementValidator_CarriesTheProfilesTolerance(
        ClientSecurityProfile profile)
    {
        ValidationParameters? captured = null;

        var tokenValidator = new Mock<IJsonWebTokenValidator>();
        tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, parameters) => captured = parameters)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "not the subject of this test"));

        var options = new Mock<IOptionsMonitor<OidcOptions>>();
        options
            .SetupGet(o => o.CurrentValue)
            .Returns(new OidcOptions
            {
                DefaultSecurityProfile = profile,
                SoftwareStatement = new SoftwareStatementOptions
                {
                    TrustedIssuers =
                    [
                        new TrustedIssuer
                        {
                            Issuer = "https://issuer.example.com",
                            JwksUri = new Uri("https://issuer.example.com/jwks"),
                        },
                    ],
                },
            });

        var validator = new SoftwareStatementValidator(
            NullLogger<SoftwareStatementValidator>.Instance,
            tokenValidator.Object,
            options.Object,
            new Mock<ISecureHttpFetcher>().Object);

        await validator.ValidateAsync(new ClientRegistrationValidationContext(
            new ClientRegistrationRequest { SoftwareStatement = "header.payload.signature" }));

        Assert.Equal(
            SecurityProfileRequirements.Resolve(profile).ClockSkewOrDefault(),
            captured.NotNull(nameof(captured)).ClockSkew);
    }

    /// <summary>
    /// The same for the private key JWT and request-object path, which is the one FAPI 2.0 governs
    /// most directly. Each construction site carries the tolerance in a line of its own, so each
    /// needs a case of its own: deleting any one of them leaves every other case green.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2)]
    [InlineData(ClientSecurityProfile.None)]
    public async Task ClientJwtValidator_CarriesTheProfilesTolerance(
        ClientSecurityProfile profile)
    {
        ValidationParameters? captured = null;

        var tokenValidator = new Mock<IJsonWebTokenValidator>();
        tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, parameters) => captured = parameters)
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "not the subject of this test"));

        var requestInfoProvider = new Mock<IRequestInfoProvider>();
        requestInfoProvider.Setup(p => p.RequestUri).Returns("https://auth.example.com");

        var issuerProvider = new Mock<IIssuerProvider>();
        issuerProvider.Setup(p => p.GetIssuer()).Returns("https://auth.example.com");

        var serviceKeys = new Mock<IAuthServiceKeysProvider>();
        serviceKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<bool>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        var validator = new ClientJwtValidator(
            NullLogger<ClientJwtValidator>.Instance,
            requestInfoProvider.Object,
            tokenValidator.Object,
            new Mock<IClientInfoProvider>().Object,
            new Mock<IClientKeysProvider>().Object,
            issuerProvider.Object,
            serviceKeys.Object,
            Options.Create(new OidcOptions { DefaultSecurityProfile = profile }));

        await validator.ValidateAsync("header.payload.signature");

        Assert.Equal(
            SecurityProfileRequirements.Resolve(profile).ClockSkewOrDefault(),
            captured.NotNull(nameof(captured)).ClockSkew);
    }

    /// <summary>
    /// Under the profile its own tolerance arrives at the validator - the asymmetric pair section
    /// 5.3.2.1 describes, rather than the symmetric default a site that forgot the line would send.
    /// </summary>
    [Fact]
    public async Task UnderTheProfile_TheProfilesToleranceReachesTheValidator()
    {
        var parameters = await CaptureParameters(ClientSecurityProfile.Fapi2);

        Assert.Equal(ClockSkew.Fapi2, parameters.ClockSkew);
    }

    /// <summary>
    /// And outside it the library default arrives, which is what keeps the case above from being
    /// satisfied by the profile's pair applied unconditionally: RFC 7523 Section 3 names no bound,
    /// so a deployment held to no profile keeps the looser window.
    /// </summary>
    [Fact]
    public async Task WithNoProfile_TheLibraryDefaultReachesTheValidator()
    {
        var parameters = await CaptureParameters(ClientSecurityProfile.None);

        Assert.Equal(ClockSkew.Default, parameters.ClockSkew);
    }
}
