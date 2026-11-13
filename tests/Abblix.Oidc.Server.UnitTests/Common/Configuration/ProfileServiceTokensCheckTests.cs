// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// FAPI 1.0 Part 2 section 8.6: "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms",
/// and FAPI 2.0 section 5.4.1 has the server use PS256, ES256 or EdDSA "when creating or processing JWTs". The tokens
/// the server signs for itself - access, refresh, registration access and initial access tokens - take the algorithm
/// the deployment configures, so a tenant where such a profile is in force is refused at startup while one of those
/// is signed with another.
/// </summary>
public class ProfileServiceTokensCheckTests
{
    private static OidcOptions OptionsSigningWith(string algorithm)
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Signing.Algorithm = algorithm;
        options.ServiceTokens.RefreshToken.Signing.Algorithm = algorithm;
        options.ServiceTokens.RegistrationAccessToken.Signing.Algorithm = algorithm;
        options.ServiceTokens.InitialAccessToken.Signing.Algorithm = algorithm;
        return options;
    }

    private static TenantDefinition Tenant(ClientSecurityProfile profile, params ClientInfo[] clients) => new TestIssuer
    {
        DefaultSecurityProfile = profile,
        Clients = clients,
    }.ToTenant();

    /// <summary>
    /// A tenant holding its clients to FAPI 1.0 Advanced at the RS256 default is refused, one naming each token's
    /// algorithm, and the same tenant signing with PS256 is not.
    /// </summary>
    [Fact]
    public void AFapiTenant_SigningItsOwnTokensRs256_IsRefused()
    {
        var check = new ProfileServiceTokensCheck();

        Assert.Equal(4, check.Check([Tenant(ClientSecurityProfile.Fapi1Advanced)], new OidcOptions()).Count());
        Assert.Empty(check.Check([Tenant(ClientSecurityProfile.Fapi1Advanced)], OptionsSigningWith(SigningAlgorithms.PS256)));
    }

    /// <summary>
    /// A tenant held to no profile is refused as well where one of its clients names one, since that client's access
    /// tokens are signed with the deployment's algorithm; a tenant with no such client keeps RS256.
    /// </summary>
    [Fact]
    public void AClientNamingAFapiProfile_HoldsTheTenantsOwnTokensToIt()
    {
        var check = new ProfileServiceTokensCheck();
        var fapiClient = new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = ClientSecurityProfile.Fapi2 };

        Assert.NotEmpty(check.Check([Tenant(ClientSecurityProfile.None, fapiClient)], new OidcOptions()));
        Assert.Empty(check.Check([Tenant(ClientSecurityProfile.None, new ClientInfo("plain"))], new OidcOptions()));
    }
}
