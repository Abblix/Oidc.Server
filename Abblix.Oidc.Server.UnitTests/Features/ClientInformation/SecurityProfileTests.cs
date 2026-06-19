// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
    }

    [Theory]
    [InlineData(ClientSecurityProfile.None, false)]
    [InlineData(ClientSecurityProfile.Fapi2, true)]
    public void For_UsesClientProfile(ClientSecurityProfile clientProfile, bool expectSenderConstrained)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = clientProfile };

        var requirements = SecurityProfileRequirements.For(client);

        Assert.Equal(expectSenderConstrained, requirements.RequireSenderConstrainedTokens);
    }

    [Fact]
    public void FindViolations_Fapi2CodeOnly_NoViolations()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
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
            ClientSecurityProfile.Fapi2);

        Assert.Empty(violations);
    }

    [Fact]
    public void FindViolations_Fapi2ImplicitOnly_FlagsMissingCodeAndImplicit()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.IdToken]],
            ClientSecurityProfile.Fapi2);

        Assert.Equal(2, violations.Count);
    }

    [Fact]
    public void FindViolations_Fapi2CodePlusHybrid_FlagsHybridOnly()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
            ClientSecurityProfile.Fapi2);

        // code is allowed, so only the implicit/hybrid violation remains.
        Assert.Single(violations);
    }

    [Fact]
    public void FindViolations_NoProfile_NeverFlags()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.IdToken]],
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
}
