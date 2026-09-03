// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// Unit tests for the security-profile core: the control bundle a profile resolves to, the
/// effective-profile fallback from client to server default, and the fail-loud response-type
/// self-consistency check.
/// </summary>
public class SecurityProfileTests
{
    [Fact]
    public void Resolve_None_RequiresNothing()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);

        Assert.False(requirements.RequirePkce);
        Assert.False(requirements.RequireS256CodeChallenge);
        Assert.False(requirements.RequirePushedAuthorizationRequests);
        Assert.False(requirements.RequireSenderConstrainedTokens);
        Assert.False(requirements.RequireCodeResponseTypeOnly);
        Assert.False(requirements.RequireStrictRequestObjectProcessing);
    }

    [Fact]
    public void Resolve_Fapi2_RequiresTheWholeBundle()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2);

        Assert.True(requirements.RequirePkce);
        Assert.True(requirements.RequireS256CodeChallenge);
        Assert.True(requirements.RequirePushedAuthorizationRequests);
        Assert.True(requirements.RequireSenderConstrainedTokens);
        Assert.True(requirements.RequireCodeResponseTypeOnly);
        Assert.True(requirements.RequireStrictRequestObjectProcessing);
    }

    [Theory]
    // clientProfile (null = unset), defaultProfile, expected effective
    [InlineData(null, ClientSecurityProfile.None, ClientSecurityProfile.None)]
    [InlineData(null, ClientSecurityProfile.Fapi2, ClientSecurityProfile.Fapi2)] // unset inherits the default
    [InlineData(ClientSecurityProfile.None, ClientSecurityProfile.Fapi2, ClientSecurityProfile.None)] // explicit None opts out
    [InlineData(ClientSecurityProfile.Fapi2, ClientSecurityProfile.None, ClientSecurityProfile.Fapi2)] // client wins
    public void For_UnsetInheritsDefault_ExplicitWins(
        ClientSecurityProfile? clientProfile,
        ClientSecurityProfile defaultProfile,
        ClientSecurityProfile expected)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = clientProfile };

        Assert.Equal(
            SecurityProfileRequirements.Resolve(expected),
            SecurityProfileRequirements.For(client, defaultProfile));
    }

    [Fact]
    public void For_UnsetClientInheritsServerDefault()
    {
        var client = new ClientInfo(TestConstants.DefaultClientId); // SecurityProfile left unset (null)

        var requirements = SecurityProfileRequirements.For(client, ClientSecurityProfile.Fapi2);

        Assert.True(requirements.RequireSenderConstrainedTokens);
    }

    [Fact]
    public void FindViolations_Fapi2CodeOnly_NoViolations()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            ClientSecurityProfile.Fapi2);

        Assert.Empty(violations);
    }

    /// <summary>
    /// The code-only check is case-insensitive, matching the runtime flow-type validator: a
    /// non-canonical "Code" casing is still recognised as the authorization-code response type.
    /// </summary>
    [Fact]
    public void FindViolations_Fapi2CodeOnlyNonCanonicalCasing_NoViolations()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [["Code"]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            ClientSecurityProfile.Fapi2);

        Assert.Empty(violations);
    }

    [Fact]
    public void FindViolations_Fapi2ImplicitOnly_FlagsMissingCodeAndImplicit()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.IdToken]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            ClientSecurityProfile.Fapi2);

        Assert.Equal(2, violations.Count);
    }

    [Fact]
    public void FindViolations_Fapi2CodePlusHybrid_FlagsHybridOnly()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            ClientSecurityProfile.Fapi2);

        // code is allowed, so only the implicit/hybrid violation remains.
        Assert.Single(violations);
    }

    [Fact]
    public void FindViolations_NoProfile_NeverFlags()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.IdToken]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            ClientSecurityProfile.None);

        Assert.Empty(violations);
    }

    [Fact]
    public void OptionsValidator_ConsistentFapi2Client_Succeeds()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo(TestConstants.DefaultClientId)
                {
                    SecurityProfile = ClientSecurityProfile.Fapi2,
                    AllowedResponseTypes = [[ResponseTypes.Code]],
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
                },
            ],
        };

        var result = new OidcOptionsSecurityProfileValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void OptionsValidator_InconsistentFapi2Client_Fails()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo(TestConstants.DefaultClientId)
                {
                    SecurityProfile = ClientSecurityProfile.Fapi2,
                    AllowedResponseTypes = [[ResponseTypes.IdToken]],
                },
            ],
        };

        var result = new OidcOptionsSecurityProfileValidator().Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>
    /// An unprofiled (None) client is not constrained even with an implicit/hybrid response type:
    /// the client's profile is authoritative and None imposes nothing, so startup validation passes.
    /// </summary>
    [Fact]
    public void OptionsValidator_UnprofiledClientWithHybrid_Succeeds()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo(TestConstants.DefaultClientId)
                {
                    AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
                },
            ],
        };

        var result = new OidcOptionsSecurityProfileValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    /// <summary>
    /// An unprofiled client inherits the server-wide DefaultSecurityProfile=FAPI 2.0; a hybrid
    /// response type then makes it inconsistent and startup validation fails.
    /// </summary>
    [Fact]
    public void OptionsValidator_GlobalDefaultFapi2_UnprofiledHybrid_Fails()
    {
        var options = new OidcOptions
        {
            DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
            Clients =
            [
                new ClientInfo(TestConstants.DefaultClientId)
                {
                    AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
                },
            ],
        };

        var result = new OidcOptionsSecurityProfileValidator().Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>
    /// A client that explicitly selects None opts out of the server-wide FAPI 2.0 default, so its
    /// hybrid response type is not constrained and startup validation passes.
    /// </summary>
    [Fact]
    public void OptionsValidator_ExplicitNoneOverridesGlobalDefault_Succeeds()
    {
        var options = new OidcOptions
        {
            DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
            Clients =
            [
                new ClientInfo(TestConstants.DefaultClientId)
                {
                    SecurityProfile = ClientSecurityProfile.None,
                    AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
                },
            ],
        };

        var result = new OidcOptionsSecurityProfileValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    /// <summary>
    /// FAPI 2.0 section 5.3.2.1: the server "shall only support confidential clients as defined in
    /// [RFC6749]". A client authenticating with nothing at the token endpoint is the public client
    /// that rule excludes, and the refusal has to reach it before it ever sends a request.
    /// </summary>
    [Fact]
    public void FindViolations_Fapi2PublicClient_Violation()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
            ClientAuthenticationMethods.None,
            ClientSecurityProfile.Fapi2);

        Assert.Contains(violations, violation => violation.Contains("confidential clients only"));
    }

    /// <summary>
    /// FAPI 2.0 section 5.3.2.1 admits mutual TLS and the private key JWT assertion, both of which
    /// prove possession of a key. Every method keyed on a shared secret is refused, whichever form
    /// it takes.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt)]
    public void FindViolations_Fapi2SharedSecretAuthentication_Violation(string method)
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
            method,
            ClientSecurityProfile.Fapi2);

        Assert.Contains(violations, violation => violation.Contains("mutual TLS or a private key JWT"));
    }

    /// <summary>
    /// The two methods the profile admits pass, which is what keeps the refusal above from being a
    /// check that refuses everything.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth)]
    [InlineData(ClientAuthenticationMethods.SelfSignedTlsClientAuth)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt)]
    public void FindViolations_Fapi2KeyBasedAuthentication_NoViolations(string method)
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
            method,
            ClientSecurityProfile.Fapi2);

        Assert.Empty(violations);
    }

    /// <summary>
    /// Neither new requirement fires without a profile, so a deployment that selects none keeps the
    /// client configurations it already has.
    /// </summary>
    [Fact]
    public void FindViolations_NoProfilePublicClient_NoViolations()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
            ClientAuthenticationMethods.None,
            ClientSecurityProfile.None);

        Assert.Empty(violations);
    }

    /// <summary>
    /// FAPI 2.0 section 5.3.2.1: the server "shall not use refresh token rotation except in
    /// extraordinary circumstances". This is the one requirement that removes a control instead of
    /// adding one.
    /// </summary>
    [Fact]
    public void Fapi2_ForbidsRefreshTokenRotation()
    {
        Assert.True(SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2)
            .ForbidRefreshTokenRotation);
    }

    /// <summary>
    /// Removing rotation is sound only because the same profile requires the two controls that
    /// stand in for it. This is the check that keeps that condition true as profiles are added or
    /// edited, and it runs at startup rather than at review time.
    /// </summary>
    [Fact]
    public void FindUnreplacedRelaxations_ShippedProfiles_None()
    {
        Assert.Empty(SecurityProfileRequirements.FindUnreplacedRelaxations());
    }

    /// <summary>
    /// The remaining two requirements are read by services rather than by the consistency check, so
    /// what is asserted here is that the profile carries them at all. A flag a profile sets and no
    /// consumer reads would ship silently unenforced, which is what the enforcement tests in the
    /// end-to-end suites answer for.
    /// </summary>
    [Fact]
    public void Fapi2_CarriesTheRemainingRequirements()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2);

        Assert.True(requirements.RequireConfidentialClient);
        Assert.True(requirements.RequireKeyBasedClientAuthentication);
        Assert.True(requirements.RequireIssuerAudienceInClientAssertion);
    }
}
