// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// The three profiles of FAPI 2.0 Message Signing: each keeps the Security Profile whole and adds the clauses of its
/// own sections.
/// </summary>
public class MessageSigningProfileTests
{
    /// <summary>
    /// A host persists the number, so no value may move: a stored client would otherwise come back under another
    /// profile.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, 0)]
    [InlineData(ClientSecurityProfile.Fapi2, 1)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, 2)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationRequests, 3)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationResponses, 4)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, 5)]
    public void ProfileNumbers_DoNotMove(ClientSecurityProfile profile, int number)
        => Assert.Equal(number, (int)profile);

    /// <summary>
    /// FAPI 2.0 Message Signing section 5: "All provisions of the [FAPI2_Security_Profile] apply to the Message
    /// Signing Profile as well". Adding the Security Profile to a signing profile changes nothing, which holds for
    /// every control the type has, including one added later.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationRequests)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationResponses)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning)]
    public void EverySigningProfile_RequiresEverythingFapi2Requires(ClientSecurityProfile profile)
    {
        var bundle = SecurityProfileRequirements.Resolve(profile);
        var client = new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = profile };

        Assert.Equal(bundle, SecurityProfileRequirements.For(client, ClientSecurityProfile.Fapi2));
        Assert.NotEqual(SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2), bundle);
    }

    /// <summary>
    /// FAPI 2.0 Message Signing section 5.3.1: a signed request object at the PAR endpoint, "the aud claim in the
    /// request object to be, or to be an array containing, the authorization server's issuer identifier URL", an nbf
    /// "no longer than 60 minutes in the past" and an exp "no longer than 60 minutes after the nbf claim"; nothing of
    /// section 5.4.1.
    /// </summary>
    [Fact]
    public void SignedAuthorizationRequests_RequireWhatSection531Requires()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2SignedAuthorizationRequests);

        Assert.True(requirements.RequireSignedRequestObject);
        Assert.True(requirements.RequirePushedAuthorizationRequests);
        Assert.True(requirements.RequireIssuerAudienceInRequestObject);
        Assert.Equal(TimeSpan.FromMinutes(60), requirements.MaxRequestObjectLifetime);
        Assert.Null(requirements.SignedAuthorizationResponseModes);
    }

    /// <summary>
    /// FAPI 2.0 Message Signing section 5.4.1: signed authorization responses "via JWT Secured Authorization Response
    /// Mode for OAuth 2.0 [JARM]", in any of its modes; nothing of section 5.3.1.
    /// </summary>
    [Fact]
    public void SignedAuthorizationResponses_RequireWhatSection541Requires()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2SignedAuthorizationResponses);

        Assert.Equal(
            [ResponseModes.FormPostJwt, ResponseModes.FragmentJwt, ResponseModes.Jwt, ResponseModes.QueryJwt],
            requirements.SignedAuthorizationResponseModes!.Order(StringComparer.Ordinal));
        Assert.False(requirements.RequireSignedRequestObject);
        Assert.False(requirements.RequireIssuerAudienceInRequestObject);
        Assert.Null(requirements.MaxRequestObjectLifetime);
    }

    /// <summary>
    /// The whole profile carries both sections.
    /// </summary>
    [Fact]
    public void MessageSigning_RequiresBothSections()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2MessageSigning);

        Assert.True(requirements.RequireSignedRequestObject);
        Assert.True(requirements.RequireIssuerAudienceInRequestObject);
        Assert.Equal(TimeSpan.FromMinutes(60), requirements.MaxRequestObjectLifetime);
        Assert.Same(SecurityProfileRequirements.EveryJwtResponseMode, requirements.SignedAuthorizationResponseModes);
    }

    /// <summary>
    /// A client restricted to response modes none of which its profile admits for a signed response can send no
    /// request the profile accepts, and is refused as misconfigured: under Message Signing a list without a JARM mode,
    /// under FAPI 1.0 Advanced one without <c>jwt</c> where the client is not registered for <c>code id_token</c>,
    /// whose ID token signs the response in any mode. No list, or no profile asking for a signed response, is not a
    /// violation.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationResponses, new[] { ResponseModes.Query }, false, 1)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationResponses, new[] { ResponseModes.Query, ResponseModes.FormPostJwt }, false, 0)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, new[] { ResponseModes.Fragment }, false, 1)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, null, false, 0)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, new[] { ResponseModes.QueryJwt }, false, 1)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, new[] { ResponseModes.Fragment }, true, 0)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationRequests, new[] { ResponseModes.Query }, false, 0)]
    [InlineData(ClientSecurityProfile.Fapi2, new[] { ResponseModes.Query }, false, 0)]
    public void FindResponseModeViolations_AListWithoutAnAdmittedMode(
        ClientSecurityProfile profile, string[]? responseModes, bool hybrid, int expected)
    {
        string[][] responseTypes = hybrid ? [[ResponseTypes.Code, ResponseTypes.IdToken]] : [[ResponseTypes.Code]];

        var violations = SecurityProfileConsistency.FindResponseModeViolations(
            responseModes, responseTypes, SecurityProfileRequirements.Resolve(profile));

        Assert.Equal(expected, violations.Count);
    }

    /// <summary>
    /// The same is refused at startup, for a client a tenant declares.
    /// </summary>
    [Theory]
    [InlineData(ResponseModes.Query, 1)]
    [InlineData(ResponseModes.QueryJwt, 0)]
    public void Check_AMessageSigningClientWithoutAJarmMode_Refuses(string responseMode, int expected)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId)
        {
            SecurityProfile = ClientSecurityProfile.Fapi2MessageSigning,
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            AllowedResponseTypes = [[ResponseTypes.Code]],
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AllowedResponseModes = [responseMode],
        };
        var tenant = new TenantDefinition { Id = "acme", Issuer = TestConstants.DefaultIssuer, Clients = [client] };

        Assert.Equal(expected, new SecurityProfileCheck().Check([tenant], new OidcOptions()).Count());
    }

    /// <summary>
    /// Under a tenant holding everyone to FAPI 1.0 Advanced, a client naming Message Signing is admitted in the modes
    /// both profiles admit: the literal <c>jwt</c> FAPI 1.0 Part 2 section 5.2.2 names. In the other direction too.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, ClientSecurityProfile.Fapi1Advanced)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, ClientSecurityProfile.Fapi2SignedAuthorizationResponses)]
    public void WithFapi1Advanced_TheModesBothAdmit(ClientSecurityProfile clientProfile, ClientSecurityProfile floor)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = clientProfile };

        Assert.Same(
            SecurityProfileRequirements.LiteralJwtResponseMode,
            SecurityProfileRequirements.For(client, floor).SignedAuthorizationResponseModes);
    }
}
