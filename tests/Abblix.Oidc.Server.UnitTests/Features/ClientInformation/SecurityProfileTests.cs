// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// Unit tests for the security-profile core: the control bundle a profile resolves to, the
/// effective-profile fallback from client to the tenant's default, and the fail-loud response-type
/// self-consistency check.
/// </summary>
public class SecurityProfileTests
{
    private static TenantDefinition Tenant(ClientSecurityProfile defaultProfile, params ClientInfo[] clients) => new()
    {
        Id = "acme",
        Issuer = TestConstants.DefaultIssuer,
        DefaultSecurityProfile = defaultProfile,
        Clients = clients,
    };

    private static List<TenantRefusal> Check(TenantDefinition tenant)
        => new SecurityProfileCheck().Check([tenant], new OidcOptions()).ToList();

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
        Assert.Null(requirements.MaxRequestObjectLifetime);
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
        Assert.Equal(TimeSpan.FromMinutes(60), requirements.MaxRequestObjectLifetime);
        Assert.False(requirements.RequireSignedRequestObject);
        Assert.False(requirements.RequireSignedAuthorizationResponse);
        Assert.False(requirements.RequireIssuerAudienceInRequestObject);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2: the server "shall require a JWS signed JWT request object", "shall only use the
    /// parameters included in the signed request object", bounds its exp and nbf by 60 minutes, "shall only issue
    /// sender-constrained access tokens", authenticates the client by mutual TLS or private_key_jwt and "shall not
    /// support public clients".
    /// </summary>
    [Fact]
    public void Resolve_Fapi1Advanced_RequiresWhatSection522Requires()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi1Advanced);

        Assert.True(requirements.RequireSignedRequestObject);
        Assert.True(requirements.RequireStrictRequestObjectProcessing);
        Assert.Equal(TimeSpan.FromMinutes(60), requirements.MaxRequestObjectLifetime);
        Assert.True(requirements.RequireSenderConstrainedTokens);
        Assert.True(requirements.RequireConfidentialClient);
        Assert.True(requirements.RequireKeyBasedClientAuthentication);
        Assert.True(requirements.RequireSignedAuthorizationResponse);
        Assert.True(requirements.RequireIssuerAudienceInRequestObject);
    }

    /// <summary>
    /// And nothing the section does not ask for: it admits <c>code id_token</c>, makes PAR optional, asks PKCE only of
    /// a pushed request, and names neither the clock window, the assertion audience nor refresh token rotation that
    /// FAPI 2.0 does. A control demanded here would refuse a client the FAPI 1.0 profile admits.
    /// </summary>
    [Fact]
    public void Resolve_Fapi1Advanced_DemandsNoFapi2OnlyControl()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi1Advanced);

        Assert.False(requirements.RequireCodeResponseTypeOnly);
        Assert.False(requirements.RequirePushedAuthorizationRequests);
        Assert.False(requirements.RequirePkce);
        Assert.False(requirements.RequireS256CodeChallenge);
        Assert.False(requirements.RequireStringAudienceInClientAssertion);
        Assert.False(requirements.ForbidRefreshTokenRotation);
        Assert.Null(requirements.MaxClockSkew);
        Assert.Equal(
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.None).DefaultClockSkew,
            requirements.DefaultClockSkew);
    }

    /// <summary>
    /// A client naming one FAPI profile under a tenant holding it to the other is held to the controls of BOTH: the
    /// signed request object only FAPI 1.0 Advanced demands, and the code-only response type only FAPI 2.0 does.
    /// Equality against either bundle cannot show this, since the combination is neither.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, ClientSecurityProfile.Fapi1Advanced)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, ClientSecurityProfile.Fapi2)]
    public void For_TwoFapiProfiles_CarryTheControlsOfEach(
        ClientSecurityProfile clientProfile,
        ClientSecurityProfile defaultProfile)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = clientProfile };

        var requirements = SecurityProfileRequirements.For(client, defaultProfile);

        Assert.True(requirements.RequireSignedRequestObject);
        Assert.True(requirements.RequireCodeResponseTypeOnly);
        Assert.True(requirements.RequireSignedAuthorizationResponse);
        Assert.True(requirements.RequireIssuerAudienceInRequestObject);
        Assert.True(requirements.RequireStringAudienceInClientAssertion);
        Assert.Equal(ClockSkew.Fapi2Ceiling, requirements.MaxClockSkew);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2 requires "the response_type value code id_token" or code with JARM, so a client
    /// held to it and registered for <c>code id_token</c> is consistent, while a shared secret and a public client
    /// are not.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, 0)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth, 0)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, 1)]
    [InlineData(ClientAuthenticationMethods.None, 2)]
    public void FindViolations_Fapi1Advanced_HybridClient(string method, int expected)
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code, ResponseTypes.IdToken]],
            method,
            ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi1Advanced));

        Assert.Equal(expected, violations.Count);
    }

    /// <summary>
    /// A deployment-wide profile is a FLOOR: a client can ask for more and never for less. The row
    /// that carries the decision is the one whose client names the empty profile - naming a profile
    /// that demands nothing, under a deployment that demands the FAPI 2.0 bundle, leaves the client
    /// held to that bundle.
    /// </summary>
    /// <remarks>
    /// The row whose client names nothing under a deployment naming the empty profile keeps the case from being
    /// satisfied by a resolution that answers the strictest bundle whatever it is asked, and the row whose client names
    /// Fapi2 under a deployment naming the empty profile by one that answers the deployment's.
    /// </remarks>
    [Theory]
    // clientProfile (null = unset), defaultProfile, expected effective
    [InlineData(null, ClientSecurityProfile.None, ClientSecurityProfile.None)]
    [InlineData(null, ClientSecurityProfile.Fapi2, ClientSecurityProfile.Fapi2)] // unset takes the floor
    [InlineData(ClientSecurityProfile.None, ClientSecurityProfile.Fapi2, ClientSecurityProfile.Fapi2)] // cannot step below it
    [InlineData(ClientSecurityProfile.Fapi2, ClientSecurityProfile.None, ClientSecurityProfile.Fapi2)] // may rise above it
    [InlineData(null, ClientSecurityProfile.Fapi1Advanced, ClientSecurityProfile.Fapi1Advanced)]
    [InlineData(ClientSecurityProfile.None, ClientSecurityProfile.Fapi1Advanced, ClientSecurityProfile.Fapi1Advanced)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, ClientSecurityProfile.None, ClientSecurityProfile.Fapi1Advanced)]
    public void For_TakesTheFloorAndWhateverTheClientAddsToIt(
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

    /// <summary>
    /// FAPI 2.0 section 5.3.2.1 has the server "only accept its issuer identifier value ... as a string in the aud
    /// claim received in client authentication assertions", so a client allowed anything beyond the issuer there -
    /// the token endpoint URL, an array, or a set lacking the issuer - is misconfigured; with no profile the same
    /// client is consistent, since RFC 10070 leaves room for a transition.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint, 1)]
    [InlineData(ClientSecurityProfile.Fapi2, ClientAssertionAudiences.Issuer | ClientAssertionAudiences.AllowArray, 1)]
    [InlineData(ClientSecurityProfile.Fapi2, ClientAssertionAudiences.TokenEndpoint, 1)]
    [InlineData(ClientSecurityProfile.Fapi2, ClientAssertionAudiences.Issuer, 0)]
    [InlineData(ClientSecurityProfile.None, ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint | ClientAssertionAudiences.AllowArray, 0)]
    public void FindViolations_AssertionAudiencesBeyondTheIssuer_AreAViolationUnderFapi2Only(
        ClientSecurityProfile profile, ClientAssertionAudiences assertionAudiences, int expected)
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            assertionAudiences,
            SecurityProfileRequirements.Resolve(profile));

        Assert.Equal(expected, violations.Count);
    }

    [Fact]
    public void FindViolations_Fapi2CodeOnly_NoViolations()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2));

        Assert.Empty(violations);
    }

    /// <summary>
    /// The code-only check is case-insensitive, matching the runtime flow-type validator: a
    /// non-canonical "Code" casing is still recognized as the authorization-code response type.
    /// </summary>
    [Fact]
    public void FindViolations_Fapi2CodeOnlyNonCanonicalCasing_NoViolations()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [["Code"]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2));

        Assert.Empty(violations);
    }

    [Fact]
    public void FindViolations_Fapi2ImplicitOnly_FlagsMissingCodeAndImplicit()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.IdToken]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2));

        Assert.Equal(2, violations.Count);
    }

    [Fact]
    public void FindViolations_Fapi2CodePlusHybrid_FlagsHybridOnly()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2));

        // code is allowed, so only the implicit/hybrid violation remains.
        Assert.Single(violations);
    }

    [Fact]
    public void FindViolations_NoProfile_NeverFlags()
    {
        var violations = SecurityProfileConsistency.FindViolations(
            [[ResponseTypes.IdToken]],
            ClientAuthenticationMethods.PrivateKeyJwt,
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.None));

        Assert.Empty(violations);
    }

    [Fact]
    public void Check_ConsistentFapi2Client_Passes()
    {
        var tenant = Tenant(
            ClientSecurityProfile.None,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.Fapi2,
                AllowedResponseTypes = [[ResponseTypes.Code]],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            });

        Assert.Empty(Check(tenant));
    }

    [Fact]
    public void Check_InconsistentFapi2Client_Refuses()
    {
        var tenant = Tenant(
            ClientSecurityProfile.None,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.Fapi2,
                AllowedResponseTypes = [[ResponseTypes.IdToken]],
            });

        var refusals = Check(tenant);

        Assert.NotEmpty(refusals);
        Assert.All(refusals, refusal => Assert.Equal("acme", Assert.Single(refusal.TenantIds)));
    }

    /// <summary>
    /// An unprofiled (None) client is not constrained even with an implicit/hybrid response type:
    /// the client's profile is authoritative and None imposes nothing, so startup validation passes.
    /// </summary>
    [Fact]
    public void Check_UnprofiledClientWithHybrid_Passes()
    {
        var tenant = Tenant(
            ClientSecurityProfile.None,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
            });

        Assert.Empty(Check(tenant));
    }

    /// <summary>
    /// The floor reaches the two controls only this walk enforces. A client naming the empty
    /// profile under a FAPI 2.0 tenant, registered to authenticate with a shared secret, is
    /// refused at startup - the profile admits confidential clients authenticating by key, and it
    /// admits them of every client the tenant serves.
    /// </summary>
    /// <remarks>
    /// These two flags have no other consumer, so a resolution that dropped the floor here would
    /// show up nowhere else: every request-time validator would refuse such a client while the
    /// server started clean, leaving the operator to learn it from refusals citing requirements no
    /// configuration of theirs sets. Worse, the client would go on holding a shared secret while
    /// the profile switched OFF its refresh token rotation, which is what the two controls this
    /// walk enforces are there to pay for.
    /// </remarks>
    [Fact]
    public void Check_TenantDefaultFapi2_ClientNamesNoneAndUsesASharedSecret_Refuses()
    {
        var tenant = Tenant(
            ClientSecurityProfile.Fapi2,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.None,
                AllowedResponseTypes = [[ResponseTypes.Code]],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            });

        Assert.Contains(Check(tenant), refusal => refusal.Message.Contains("private key JWT"));
    }

    /// <summary>
    /// The other control this walk owns, given its own case: a client authenticating with NOTHING is
    /// the public client the profile excludes, and the floor reaches it too.
    /// <see cref="Check_TenantDefaultFapi2_ClientNamesNoneAndUsesASharedSecret_Refuses"/> cannot
    /// stand for this one - it uses a shared secret, which is a confidential client by RFC 6749 and
    /// trips the key-based requirement alone, so removing the confidential-client arm would leave it
    /// green.
    /// </summary>
    [Fact]
    public void Check_TenantDefaultFapi2_ClientNamesNoneAndAuthenticatesWithNothing_Refuses()
    {
        var tenant = Tenant(
            ClientSecurityProfile.Fapi2,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.None,
                AllowedResponseTypes = [[ResponseTypes.Code]],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            });

        Assert.Contains(Check(tenant), refusal => refusal.Message.Contains("confidential clients only"));
    }

    /// <summary>
    /// The control for the shared-secret case: the same client under a tenant naming no profile
    /// starts clean, without which that case would be satisfied by a walk refusing every
    /// shared-secret client whatever the tenant demands.
    /// </summary>
    [Fact]
    public void Check_NoTenantDefault_ClientNamesNoneAndUsesASharedSecret_Passes()
    {
        var tenant = Tenant(
            ClientSecurityProfile.None,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.None,
                AllowedResponseTypes = [[ResponseTypes.Code]],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            });

        Assert.Empty(Check(tenant));
    }

    /// <summary>
    /// An unprofiled client inherits the tenant's DefaultSecurityProfile=FAPI 2.0; a hybrid
    /// response type then makes it inconsistent and startup validation fails.
    /// </summary>
    [Fact]
    public void Check_TenantDefaultFapi2_UnprofiledHybrid_Refuses()
    {
        var tenant = Tenant(
            ClientSecurityProfile.Fapi2,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
            });

        Assert.NotEmpty(Check(tenant));
    }

    /// <summary>
    /// A client naming the empty profile under a tenant's FAPI 2.0 default is refused at startup
    /// for its hybrid response type, the same as one naming no profile at all. The tenant's
    /// profile is a floor, and naming a profile that demands nothing adds nothing to it.
    /// </summary>
    [Fact]
    public void Check_ExplicitNoneUnderTenantDefault_StillRefuses()
    {
        var tenant = Tenant(
            ClientSecurityProfile.Fapi2,
            new ClientInfo(TestConstants.DefaultClientId)
            {
                SecurityProfile = ClientSecurityProfile.None,
                AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
            });

        Assert.NotEmpty(Check(tenant));
    }

    /// <summary>
    /// A client allowed the token endpoint URL as its assertion's audience is refused at startup under FAPI 2.0,
    /// whose section 5.3.2.1 accepts the issuer identifier alone, and passes at a tenant naming no profile.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, true)]
    [InlineData(ClientSecurityProfile.None, false)]
    public void Check_TokenEndpointAudienceException_IsRefusedUnderFapi2Only(ClientSecurityProfile profile, bool refused)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            ClientAssertionAudiences = ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint,
        };

        var refusals = Check(Tenant(profile, client));

        Assert.Equal(refused, refusals.Count > 0);
    }

    /// <summary>
    /// The default is a tenant's own, so a client is held to the floor of the tenant that lists it and to no
    /// other: the same hybrid client is refused at the FAPI 2.0 tenant and passes at the tenant naming no profile.
    /// </summary>
    [Fact]
    public void Check_EachTenantHoldsItsClientsToItsOwnDefault()
    {
        var hybrid = new ClientInfo(TestConstants.DefaultClientId)
        {
            AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
        };
        var strict = Tenant(ClientSecurityProfile.Fapi2, hybrid);
        var lenient = new TenantDefinition
        {
            Id = "globex",
            Issuer = new Uri("https://globex.example.com"),
            Clients = [hybrid],
        };

        var refusals = new SecurityProfileCheck().Check([strict, lenient], new OidcOptions()).ToList();

        Assert.NotEmpty(refusals);
        Assert.All(refusals, refusal => Assert.Equal("acme", Assert.Single(refusal.TenantIds)));
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
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2));

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
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2));

        Assert.Contains(violations, violation => violation.Contains("mutual TLS or a private key JWT"));
    }

    /// <summary>
    /// The two methods the profile admits pass, which is what keeps the refusal in
    /// <see cref="FindViolations_Fapi2SharedSecretAuthentication_Violation"/> from being a check that
    /// refuses everything.
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
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2));

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
            assertionAudiences: ClientAssertionAudiences.Issuer,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.None));

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
    /// The requirements below are read by services rather than by the consistency check, so what is
    /// asserted here is that the profile carries them at all. That the audience form has a consumer that
    /// reads it is answered by the FAPI 2.0 audience cases in
    /// <see cref="ClientAuthentication.PrivateKeyJwtAuthenticatorTests"/>.
    /// </summary>
    [Fact]
    public void Fapi2_CarriesTheRemainingRequirements()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2);

        Assert.True(requirements.RequireConfidentialClient);
        Assert.True(requirements.RequireKeyBasedClientAuthentication);
        Assert.True(requirements.RequireStringAudienceInClientAssertion);
    }
    /// <summary>
    /// The mistake the guard exists to catch, driven directly: a profile that drops rotation and
    /// carries neither control that replaces it. It cannot be expressed through the profiles that
    /// ship, since those are correct, so the walk takes its pairs from the caller.
    /// </summary>
    [Fact]
    public void FindUnreplacedRelaxations_RotationDroppedWithNoReplacement_NamesBothControls()
    {
        var violations = SecurityProfileRequirements.FindUnreplacedRelaxations(
            [("Unpaid", new SecurityProfileRequirements { ForbidRefreshTokenRotation = true })]);

        Assert.Equal(2, violations.Count);
        Assert.Contains(violations, v => v.Contains("confidential client"));
        Assert.Contains(violations, v => v.Contains("sender-constrained token"));
    }

    /// <summary>
    /// One control present and the other missing is still a violation, and only the missing one is
    /// named. Without this the guard could pass by requiring either control rather than both.
    /// </summary>
    [Theory]
    [InlineData(true, false, "sender-constrained token")]
    [InlineData(false, true, "confidential client")]
    public void FindUnreplacedRelaxations_OneControlMissing_NamesThatControlAlone(
        bool confidential, bool senderConstrained, string expected)
    {
        var violations = SecurityProfileRequirements.FindUnreplacedRelaxations(
        [
            ("Half", new SecurityProfileRequirements
            {
                ForbidRefreshTokenRotation = true,
                RequireConfidentialClient = confidential,
                RequireSenderConstrainedTokens = senderConstrained,
            }),
        ]);

        Assert.Single(violations);
        Assert.Contains(expected, violations[0]);
    }

    /// <summary>
    /// The library's own profiles pass the same walk at startup, through the validator a server registers, so a
    /// profile edited into an unpaid relaxation stops the server rather than shipping.
    /// </summary>
    [Fact]
    public void RelaxationsValidator_ShippedProfiles_Succeeds()
    {
        Assert.True(new SecurityProfileRelaxationsValidator().Validate(null, new OidcOptions()).Succeeded);
    }

    /// <summary>
    /// The configuration binder binds a NUMBER outside an enum's range as it stands - only a name it
    /// does not know throws - so a profile value nothing defines reaches the tenant's definition. Startup
    /// has to name it: every reader of the profile refuses such a value, and without this check the
    /// tenant starts and answers 500 to the first request that carries a client.
    /// </summary>
    [Fact]
    public void Check_UndefinedDefaultProfile_Refuses()
    {
        // With a client on the tenant, because the case this check is for is a tenant that HAS clients
        // inheriting the default, and each of them must be named without the walk resolving the value.
        var tenant = Tenant(
            (ClientSecurityProfile)7,
            new ClientInfo("client-1")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            });

        Assert.Contains(Check(tenant), refusal => refusal.Message.Contains("DefaultSecurityProfile"));
    }

    /// <summary>
    /// The same for a client naming its own profile, and it is checked whether or not the tenant's
    /// default is sound.
    /// </summary>
    [Fact]
    public void Check_UndefinedClientProfile_Refuses()
    {
        var tenant = Tenant(
            ClientSecurityProfile.None,
            new ClientInfo("client-1")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
                SecurityProfile = (ClientSecurityProfile)9,
            });

        Assert.Contains(Check(tenant), refusal => refusal.Message.Contains("client-1"));
    }

    /// <summary>
    /// Both defined profiles pass, which is what keeps <see cref="Check_UndefinedDefaultProfile_Refuses"/>
    /// and <see cref="Check_UndefinedClientProfile_Refuses"/> from being a check that refuses every
    /// tenant.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced)]
    public void Check_DefinedProfile_Passes(ClientSecurityProfile profile)
    {
        Assert.Empty(Check(Tenant(profile)));
    }

    /// <summary>
    /// A value the enum does not define arrives from outside - the configuration binder takes a
    /// number outside the range as it stands, and a client store the host writes can hold anything.
    /// Resolving it must not throw, because the readers meeting it are serving a live request and
    /// four of them sit on the authorization endpoint, where there is no client authentication to
    /// put a guard in front of. Every one of those would have answered 500.
    /// </summary>
    [Theory]
    [InlineData(7)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void Resolve_UndefinedProfile_FailsClosedInsteadOfThrowing(int value)
    {
        var requirements = SecurityProfileRequirements.Resolve((ClientSecurityProfile)value);

        Assert.True(requirements.RequirePkce);
        Assert.True(requirements.RequireS256CodeChallenge);
        Assert.True(requirements.RequirePushedAuthorizationRequests);
        Assert.True(requirements.RequireSenderConstrainedTokens);
        Assert.True(requirements.RequireCodeResponseTypeOnly);
        Assert.True(requirements.RequireStrictRequestObjectProcessing);
        Assert.True(requirements.RequireConfidentialClient);
        Assert.True(requirements.RequireKeyBasedClientAuthentication);
        Assert.True(requirements.RequireStringAudienceInClientAssertion);
    }

    /// <summary>
    /// The one flag that REMOVES a control is not demanded by the fallback: demanding it would make
    /// the bundle meant to be the strongest available weaker than the profile that ships.
    /// </summary>
    [Fact]
    public void Resolve_UndefinedProfile_DoesNotDropRefreshTokenRotation()
    {
        Assert.False(SecurityProfileRequirements.Resolve((ClientSecurityProfile)7)
            .ForbidRefreshTokenRotation);
    }

    /// <summary>
    /// A value the enum DOES define with no bundle declared is the other population: a mistake in
    /// this file rather than data from a host, and it has to be loud while the author is still here.
    /// It cannot be expressed through the enum, because every value that ships has a bundle, so the
    /// bundle comes from the caller.
    /// </summary>
    [Fact]
    public void Resolve_DefinedProfileWithNoBundle_Throws()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2, declared: null));

        Assert.Contains(nameof(ClientSecurityProfile.Fapi2), error.Message);
    }

    /// <summary>
    /// And the refusal is about the missing bundle rather than about the profile being unusual: a
    /// defined value WITH one resolves to exactly it.
    /// </summary>
    [Fact]
    public void Resolve_DefinedProfileWithABundle_ReturnsIt()
    {
        var declared = new SecurityProfileRequirements { RequirePkce = true };

        Assert.Same(
            declared,
            SecurityProfileRequirements.Resolve(ClientSecurityProfile.None, declared));
    }

    /// <summary>
    /// Every profile that ships resolves, which is what keeps the refusal in
    /// <see cref="Resolve_DefinedProfileWithNoBundle_Throws"/> from being a case nobody meets: a value added to the
    /// enum without a bundle fails here and at startup.
    /// </summary>
    [Fact]
    public void Resolve_EveryShippedProfile_Resolves()
    {
        foreach (var profile in Enum.GetValues<ClientSecurityProfile>())
        {
            Assert.NotNull(SecurityProfileRequirements.Resolve(profile));
        }
    }

    /// <summary>
    /// The client-facing entry point every reader goes through carries the same answer, so a client
    /// out of a store reaches the authorization endpoint constrained rather than crashing it.
    /// </summary>
    [Fact]
    public void For_ClientWithAnUndefinedProfile_FailsClosed()
    {
        var client = new ClientInfo("stored") { SecurityProfile = (ClientSecurityProfile)7 };

        var requirements = SecurityProfileRequirements.For(client, ClientSecurityProfile.None);

        Assert.True(requirements.RequirePkce);
        Assert.True(requirements.RequireConfidentialClient);
    }
}
