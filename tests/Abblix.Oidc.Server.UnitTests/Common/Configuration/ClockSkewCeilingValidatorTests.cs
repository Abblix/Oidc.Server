// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Xunit;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Where a profile names a bound the validator holds it whatever a caller asks for, so this guard is
/// not what makes the requirement true. It is what keeps a deployment from reading a setting back and
/// believing a number the validator will not honour - and it says nothing at all to a deployment held
/// to no bounding profile, which RFC 7523 Section 3 leaves free to choose.
/// </summary>
public class ClockSkewCeilingValidatorTests
{
    private static ValidateOptionsResult Validate(
        TimeSpan? skew,
        ClientSecurityProfile profile = ClientSecurityProfile.Fapi2)
        => new ClockSkewCeilingValidator().Validate(
            null,
            new OidcOptions
            {
                DefaultSecurityProfile = profile,
                JwtBearer = new JwtBearerOptions { ClockSkew = skew },
            });

    /// <summary>
    /// Both ends of the permitted range and the default pass, so the refusals below cannot be
    /// satisfied by a guard that refuses everything.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(59)]
    [InlineData(60)]
    public void WithinTheRange_Succeeds(int seconds)
    {
        Assert.False(Validate(TimeSpan.FromSeconds(seconds)).Failed);
    }

    /// <summary>
    /// A second past the bound is refused, and the message names the setting so the operator edits a
    /// number rather than reads the validator.
    /// </summary>
    [Theory]
    [InlineData(61)]
    [InlineData(300)]
    public void AboveTheCeiling_Fails(int seconds)
    {
        var result = Validate(TimeSpan.FromSeconds(seconds));

        Assert.True(result.Failed);
        Assert.Contains(nameof(JwtBearerOptions.ClockSkew), result.FailureMessage!);
    }

    /// <summary>
    /// The value a deployment gets by saying nothing is still refused when it is SAID under a
    /// bounding profile. The two are not the same act: nothing set asks the profile to decide and
    /// gets what the profile allows, while the same number typed into the configuration is a
    /// deployment asking for a window this profile does not permit.
    /// </summary>
    [Fact]
    public void TheLibraryDefault_SetExplicitly_Fails()
    {
        Assert.True(Validate(TimeSpan.FromMinutes(5)).Failed);
    }

    /// <summary>
    /// And outside a profile that bounds this, the same values pass. RFC 7523 Section 3 allows for
    /// clock skew and names no bound, so a deployment held to no profile is entitled to them -
    /// without this case the guard would be refusing on its own authority rather than the profile's.
    /// </summary>
    [Theory]
    [InlineData(300)]
    [InlineData(3600)]
    public void WithNoProfile_AnythingPasses(int seconds)
    {
        Assert.False(
            Validate(TimeSpan.FromSeconds(seconds), ClientSecurityProfile.None).Failed);
    }

    /// <summary>
    /// A negative value is refused whatever the profile: it is not a loosening somebody may want but
    /// a window that refuses an assertion valid at the instant its request arrives.
    /// </summary>
    [Fact]
    public void WithNoProfile_NegativeStillFails()
    {
        Assert.True(Validate(TimeSpan.FromSeconds(-1), ClientSecurityProfile.None).Failed);
    }

    /// <summary>
    /// A negative window refuses an assertion valid at the instant its request arrives, which reads
    /// as an intermittent fault rather than as a setting.
    /// </summary>
    [Fact]
    public void Negative_Fails()
    {
        Assert.True(Validate(TimeSpan.FromSeconds(-1)).Failed);
    }

    /// <summary>
    /// Nothing set is not a value to refuse: it asks the profile to decide, and what the profile
    /// decides is by construction what the profile allows. Refusing it would fail every deployment
    /// held to a bounding profile over a number nobody chose - which is what a default written into
    /// the options object would have been.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    public void NothingSet_Passes(ClientSecurityProfile profile)
    {
        Assert.False(Validate(null, profile).Failed);
    }

    /// <summary>
    /// And what nothing-set resolves to: the library's own default in both directions where no
    /// profile prescribes a tolerance, and the pair the profile names where one does. Both halves
    /// are asserted, because FAPI 2.0 section 5.3.2.1 makes them different numbers, and a case
    /// reading one half passes on a symmetric answer.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, 300, 300)]
    [InlineData(ClientSecurityProfile.Fapi2, 0, 10)]
    public void NothingSet_ResolvesToTheProfilesAnswer(
        ClientSecurityProfile profile, int pastSeconds, int futureSeconds)
    {
        var options = new JwtBearerOptions();

        var skew = options.ResolveClockSkew(profile);

        Assert.Equal(TimeSpan.FromSeconds(pastSeconds), skew.Past);
        Assert.Equal(TimeSpan.FromSeconds(futureSeconds), skew.Future);
    }

    /// <summary>
    /// What each profile carries, as a table, because the two numbers come from one sentence and are
    /// easy to collapse into each other: FAPI 2.0 section 5.3.2.1 names one tolerance a server shall
    /// accept and, separately, the furthest anything may be dated. Resolving to the ceiling would be
    /// the most permissive value allowed rather than the value named, and would still pass every
    /// other case here.
    ///
    /// Selecting no profile is a posture too, not the absence of one: the library default and no
    /// ceiling, which is what an assertion from an issuer whose clock this server does not run is
    /// entitled to under RFC 7523 Section 3.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, 300, 300, null)]
    [InlineData(ClientSecurityProfile.Fapi2, 0, 10, 60)]
    public void EachProfileCarriesItsOwnToleranceAndCeiling(
        ClientSecurityProfile profile, int pastSeconds, int futureSeconds, int? ceilingSeconds)
    {
        var requirements = SecurityProfileRequirements.Resolve(profile);

        Assert.Equal(
            TimeSpan.FromSeconds(pastSeconds),
            requirements.DefaultClockSkew.Past);

        Assert.Equal(
            TimeSpan.FromSeconds(futureSeconds),
            requirements.DefaultClockSkew.Future);

        Assert.Equal(
            ceilingSeconds is { } seconds ? TimeSpan.FromSeconds(seconds) : (TimeSpan?)null,
            requirements.MaxClockSkew);
    }

    /// <summary>
    /// The two numbers the profiles carry, named here rather than computed from the code that
    /// supplies them. Every other case in this file compares one resolution against another and
    /// would stay green if both moved together - so this is the only place the values themselves
    /// are held to what was agreed: no profile grants five minutes either way, and FAPI 2.0 section
    /// 5.3.2.1 grants nothing backward and ten seconds forward, bounded at sixty.
    /// </summary>
    [Fact]
    public void TheProfilesCarryTheAgreedNumbers()
    {
        var unprofiled = SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);

        Assert.Equal(TimeSpan.FromMinutes(5), unprofiled.DefaultClockSkew.Past);
        Assert.Equal(TimeSpan.FromMinutes(5), unprofiled.DefaultClockSkew.Future);
        Assert.Null(unprofiled.MaxClockSkew);

        var fapi = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2);

        Assert.Equal(TimeSpan.Zero, fapi.DefaultClockSkew.Past);
        Assert.Equal(TimeSpan.FromSeconds(10), fapi.DefaultClockSkew.Future);
        Assert.Equal(TimeSpan.FromSeconds(60), fapi.MaxClockSkew);
    }

    /// <summary>
    /// The ceiling is applied where the tolerance is resolved, so a value above it comes back cut
    /// down rather than travelling onward beside a bound somebody must remember to pass. This is the
    /// case that would go on passing if the bound were dropped from the resolution: the startup
    /// guard below refuses such a value only for the SERVER's own profile, while a client carrying a
    /// profile of its own reaches this path with a value nothing refused.
    /// </summary>
    [Fact]
    public void AValueAboveTheCeiling_ComesBackBounded()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2);

        var resolved = requirements.ClockSkewOrDefault(TimeSpan.FromMinutes(5));

        Assert.Equal(requirements.MaxClockSkew, resolved.Past);
        Assert.Equal(requirements.MaxClockSkew, resolved.Future);
    }

    /// <summary>
    /// And where the profile names no ceiling the same value comes back untouched, without which the
    /// case above would be satisfied by a bound applied to everything.
    /// </summary>
    [Fact]
    public void WithNoCeiling_TheValueIsUntouched()
    {
        var asked = TimeSpan.FromMinutes(5);

        var resolved = SecurityProfileRequirements
            .Resolve(ClientSecurityProfile.None)
            .ClockSkewOrDefault(asked);

        Assert.Equal(asked, resolved.Past);
        Assert.Equal(asked, resolved.Future);
    }

    /// <summary>
    /// A value under the ceiling is not cut down to it, which is what keeps the first case from
    /// being satisfied by a resolution that answers the ceiling whatever it is asked.
    /// </summary>
    [Fact]
    public void AValueUnderTheCeiling_IsKept()
    {
        var asked = TimeSpan.FromSeconds(5);

        var resolved = SecurityProfileRequirements
            .Resolve(ClientSecurityProfile.Fapi2)
            .ClockSkewOrDefault(asked);

        Assert.Equal(asked, resolved.Past);
        Assert.Equal(asked, resolved.Future);
    }

    /// <summary>
    /// And the prescribed value is strictly inside the ceiling wherever both are named, which is
    /// what makes them two facts rather than one written twice.
    /// </summary>
    [Fact]
    public void TheProfilePrescribesLessThanItPermits()
    {
        var requirements = SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi2);

        Assert.True(requirements.DefaultClockSkew.Past < requirements.MaxClockSkew);
        Assert.True(requirements.DefaultClockSkew.Future < requirements.MaxClockSkew);
    }

    /// <summary>
    /// A replay reservation has to outlive the window in which the thing it names could still be
    /// accepted, and the widest such window belongs to a client held to NO bounding profile - which
    /// a deployment under a bounding one still may have. Resolving the retention from the
    /// deployment's own profile would leave exactly that client replayable in the gap between the
    /// two, which is a hole rather than a tidy cache.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    public void RetentionCoversTheLoosestClientWindow(ClientSecurityProfile serverProfile)
    {
        var options = new OidcOptions { DefaultSecurityProfile = serverProfile };
        var optedOutClient = new ClientInfo("client-1") { SecurityProfile = ClientSecurityProfile.None };

        var accepted = options.JwtBearer.ResolveClockSkew(
            optedOutClient.SecurityProfile ?? options.DefaultSecurityProfile).Past;

        var retained = options.JwtBearer.ClockSkew
                       ?? SecurityProfileRequirements
                           .Resolve(ClientSecurityProfile.None)
                           .DefaultClockSkew.Past;

        Assert.True(
            accepted <= retained,
            $"a reservation kept for {retained} would expire while an assertion is still accepted "
            + $"for {accepted}");
    }

    /// <summary>
    /// A value this deployment set wins over both, which is the point of being able to set one.
    /// </summary>
    [Fact]
    public void AValueSet_WinsOverTheProfile()
    {
        var options = new JwtBearerOptions { ClockSkew = TimeSpan.FromSeconds(30) };

        // One number set by a host means it both ways: the asymmetry belongs to the profile's own
        // prescription, not to a value somebody typed.
        Assert.Equal(
            (ClockSkew)TimeSpan.FromSeconds(30),
            options.ResolveClockSkew(ClientSecurityProfile.Fapi2));
    }
}
