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

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// The profile names the bound and the JWT validator honours it, and each of those has its own
/// cases. Neither says the bound TRAVELS from one to the other, which is the seam a construction
/// site sits on: removing the line that carries it leaves both halves green.
/// </summary>
public class ProfileClockCeilingReachesValidationTests
{
    /// <summary>
    /// Captures the parameters a client-assertion authenticator hands the JWT validator, which is
    /// where the profile's bound has to appear if it reaches anything at all.
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
    /// Under the profile the bound arrives at the validator, carrying the number section 5.3.2.1
    /// names rather than a boolean each reader would have to expand for itself.
    /// </summary>
    [Fact]
    public async Task UnderTheProfile_TheBoundReachesTheValidator()
    {
        var parameters = await CaptureParameters(ClientSecurityProfile.Fapi2);

        Assert.Equal(TimeSpan.FromSeconds(60), parameters.MaxClockOffsetAhead);
    }

    /// <summary>
    /// And outside it none arrives, which is what keeps the case above from being satisfied by a
    /// bound applied unconditionally: RFC 7523 Section 3 names none, so a deployment held to no
    /// profile keeps whatever skew it configured.
    /// </summary>
    [Fact]
    public async Task WithNoProfile_NoBoundReachesTheValidator()
    {
        var parameters = await CaptureParameters(ClientSecurityProfile.None);

        Assert.Null(parameters.MaxClockOffsetAhead);
    }
}
