// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Named validation profiles: the mechanism that lets consumers with CONTRADICTORY demands - one
/// requires the claim the other forbids - validate side by side in one host.
/// </summary>
public class ValidationProfileTests
{
    /// <summary>Stands in for a consumer's replacement step; never runs in these tests.</summary>
    private sealed class RequireExpStep : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context, CancellationToken cancellationToken)
            => throw new NotSupportedException("Composition tests never run steps.");
    }

    private sealed class PinIssuerStep : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context, CancellationToken cancellationToken)
            => throw new NotSupportedException("Composition tests never run steps.");
    }

    private static ServiceCollection Host(Action<SecurityEventsOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Mock.Of<IIssuerKeyResolver>());
        services.AddSecurityEvents(configure);
        return services;
    }

    /// <summary>
    /// The scenario profiles exist for: one consumer REPLACES a critical step in its profile,
    /// another needs that same step intact in its own - and each resolves a validator arranged
    /// its own way, in one container, regardless of who registered first.
    /// </summary>
    [Fact]
    public void TwoContradictoryProfiles_ResolveSideBySide()
    {
        var services = Host();

        // The first consumer requires exp - Back-Channel Logout's shape.
        services.AddSecurityEventValidationProfile("logout", profile =>
        {
            profile.UseDefaultPipeline();
            profile.Steps.Replace<ExpAbsenceStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, RequireExpStep>());
            profile.AllowInsecureValidation<ExpAbsenceStep>(
                "The test replaces exp-absence, standing in for Back-Channel Logout.");
        });

        // The second keeps the default, where exp is forbidden - a SET receiver's shape.
        services.AddSecurityEventValidationProfile("set-receiver", profile => profile.UseDefaultPipeline());

        var provider = services.BuildServiceProvider();

        var logoutSteps = provider.Decompose<ISecurityEventTokenValidator>("logout")
            .Select(step => step.GetType()).ToArray();
        var receiverSteps = provider.Decompose<ISecurityEventTokenValidator>("set-receiver")
            .Select(step => step.GetType()).ToArray();

        Assert.Contains(typeof(RequireExpStep), logoutSteps);
        Assert.DoesNotContain(typeof(ExpAbsenceStep), logoutSteps);
        Assert.Contains(typeof(ExpAbsenceStep), receiverSteps);
        Assert.DoesNotContain(typeof(RequireExpStep), receiverSteps);

        Assert.NotNull(provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("logout"));
        Assert.NotNull(provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("set-receiver"));
    }

    /// <summary>
    /// A profile copies the DEFAULTS, never a sibling profile's current state: one consumer's
    /// edits must not leak into a copy whose owner reasons from the documented baseline.
    /// </summary>
    [Fact]
    public void AProfile_CopiesTheDefaults_NotASiblingProfile()
    {
        var services = Host();

        services.AddSecurityEventValidationProfile("edited", profile =>
            profile.UseDefaultPipeline().Steps.AddAfter<ParseStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, PinIssuerStep>()));

        services.AddSecurityEventValidationProfile("clean", profile => profile.UseDefaultPipeline());

        var profileSteps = services.BuildServiceProvider()
            .Decompose<ISecurityEventTokenValidator>("clean")
            .Select(step => step.GetType()).ToArray();

        Assert.DoesNotContain(typeof(PinIssuerStep), profileSteps);
    }

    /// <summary>
    /// A profile that drops one of ITS critical steps is held to an allowance of ITS OWN: a
    /// sibling profile's allowance must not excuse it.
    /// </summary>
    [Fact]
    public void AProfileDroppingACriticalStep_NeedsItsOwnAllowance()
    {
        var services = Host();

        // A sibling records an allowance of its own; it must not leak into "weakened".
        services.AddSecurityEventValidationProfile("sibling", profile =>
            profile.UseDefaultPipeline().AllowInsecureValidation<SignatureStep>(
                "An allowance recorded for a SIBLING; the profile below must not inherit it."));

        services.AddSecurityEventValidationProfile(
            "weakened", profile => profile.UseDefaultPipeline().Steps.Remove<SignatureStep>());

        var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("weakened"));
        Assert.Contains(nameof(SignatureStep), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>The same weakening constructs once the PROFILE records the reason.</summary>
    [Fact]
    public void AProfileDroppingACriticalStep_WithItsOwnAllowance_Constructs()
    {
        var services = Host();

        services.AddSecurityEventValidationProfile("weakened", profile =>
        {
            profile.UseDefaultPipeline();
            profile.Steps.Remove<SignatureStep>();
            profile.AllowInsecureValidation<SignatureStep>(
                "The test weakens its own profile and says so here.");
        });

        Assert.NotNull(services.BuildServiceProvider()
            .GetRequiredKeyedService<ISecurityEventTokenValidator>("weakened"));
    }

    /// <summary>
    /// The guarantee listing rests on: a profile that never lists a security-critical default is
    /// judged exactly as one that removed it.
    /// </summary>
    /// <remarks>
    /// Without this, listing would be the way around the guard - the step would simply not be
    /// there, with nothing to notice its absence - and the guard would only ever catch the author
    /// who reached for the removal door. It is also what makes a critical default added to the
    /// core LATER a decision for every profile's owner rather than a step injected into profiles
    /// designed before it existed.
    /// </remarks>
    [Fact]
    public void AProfileOmittingACriticalStep_NeedsAnAllowance_AsIfItHadRemovedIt()
    {
        var services = Host();

        // The documented order, minus the signature, listed rather than edited.
        services.AddSecurityEventValidationProfile("omitting", profile => profile
            .Use<ParseStep>()
            .Use<TypHeaderStep>()
            .Use<ExpAbsenceStep>()
            .Use<EventsPresenceStep>()
            .Use<JwtIdPresenceStep>()
            .Use<IssuerAllowlistStep>()
            .Use<AudienceStep>()
            .Use<IssuedAtWindowStep>()
            .Use<PayloadDeserializationStep>());

        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("omitting"));

        Assert.Contains(nameof(SignatureStep), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A profile that lists nothing is refused where it is written, not where its first token is.
    /// </summary>
    /// <remarks>
    /// Composing an empty family is a no-op rather than an error, so such a profile would end up
    /// with no validator at all - and the shape is reachable exactly because steps are listed now
    /// rather than inherited.
    /// </remarks>
    [Fact]
    public void AProfileListingNoSteps_IsRefusedNamingBothDoors()
    {
        var services = Host();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddSecurityEventValidationProfile("empty"));

        Assert.Contains(nameof(ValidationProfile.Use), refusal.Message, StringComparison.Ordinal);
        Assert.Contains(
            nameof(Infrastructure.ServiceCollectionExtensions.UseDefaultPipeline),
            refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A critical step declared FOR a profile binds to that profile alone - a sibling profile's
    /// guard must not start demanding another consumer's steps.
    /// </summary>
    [Fact]
    public void AProfileScopedCriticalStep_DoesNotBindASiblingProfile()
    {
        var services = Host();

        services.AddSecurityEventValidationProfile("strict", profile =>
        {
            profile.UseDefaultPipeline();
            profile.Steps.AddLast(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ProfileCriticalStep>());
            profile.AddCriticalStep<ProfileCriticalStep>();
        });

        // The sibling lacks ProfileCriticalStep and must still construct without any allowance:
        // the declaration was scoped to "strict".
        services.AddSecurityEventValidationProfile("sibling", profile => profile.UseDefaultPipeline());

        Assert.NotNull(services.BuildServiceProvider()
            .GetRequiredKeyedService<ISecurityEventTokenValidator>("sibling"));
    }

    private sealed class ProfileCriticalStep : ISecurityCriticalValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context, CancellationToken cancellationToken)
            => throw new NotSupportedException("Composition tests never run steps.");
    }

    /// <summary>A second registration under a taken key is refused: a profile has one owner.</summary>
    [Fact]
    public void ASecondProfile_UnderTheSameKey_IsRefused()
    {
        var services = Host();
        services.AddSecurityEventValidationProfile("taken", profile => profile.UseDefaultPipeline());

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddSecurityEventValidationProfile("taken"));
        Assert.Contains("taken", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>Without the defaults to copy there is no profile to build, and the message names the cure.</summary>
    [Fact]
    public void AProfileWithoutAddSecurityEvents_IsRefusedNamingTheCure()
    {
        var services = new ServiceCollection();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddSecurityEventValidationProfile("orphan"));
        Assert.Contains("AddSecurityEvents", refusal.Message, StringComparison.Ordinal);
    }
}
