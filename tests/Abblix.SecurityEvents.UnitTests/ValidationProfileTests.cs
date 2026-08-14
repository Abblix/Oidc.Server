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
    /// The scenario profiles exist for: one consumer REPLACES a critical step in the plain
    /// family, another needs that same step intact - and each resolves a validator arranged its
    /// own way, in one container, regardless of who registered first.
    /// </summary>
    [Fact]
    public void TwoContradictoryProfiles_ResolveSideBySide()
    {
        var services = Host(options => options.AllowInsecureValidation(
            "The test replaces exp-absence in the plain family, standing in for Back-Channel Logout."));

        // The first consumer shapes the PLAIN family: exp becomes required.
        services.Decompose<ISecurityEventTokenValidator>()
            .Replace<ExpAbsenceStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, RequireExpStep>());

        // The second creates its own profile, where the default exp-absence step must survive.
        services.AddSecurityEventValidationProfile("second");

        var provider = services.BuildServiceProvider();

        var plainSteps = provider.Decompose<ISecurityEventTokenValidator>()
            .Select(step => step.GetType()).ToArray();
        var profileSteps = provider.Decompose<ISecurityEventTokenValidator>("second")
            .Select(step => step.GetType()).ToArray();

        Assert.Contains(typeof(RequireExpStep), plainSteps);
        Assert.DoesNotContain(typeof(ExpAbsenceStep), plainSteps);
        Assert.Contains(typeof(ExpAbsenceStep), profileSteps);
        Assert.DoesNotContain(typeof(RequireExpStep), profileSteps);

        // Both singular validators construct: the plain one under its options allowance, the
        // profile untouched and needing none.
        Assert.NotNull(provider.GetRequiredService<ISecurityEventTokenValidator>());
        Assert.NotNull(provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("second"));
    }

    /// <summary>
    /// A profile copies the DEFAULTS, not the plain family's current state: another consumer's
    /// edits must not leak into a copy whose owner reasons from the documented baseline.
    /// </summary>
    [Fact]
    public void AProfile_CopiesTheDefaults_NotTheEditedFamily()
    {
        var services = Host();

        services.Decompose<ISecurityEventTokenValidator>()
            .AddAfter<ParseStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, PinIssuerStep>());

        services.AddSecurityEventValidationProfile("clean");

        var profileSteps = services.BuildServiceProvider()
            .Decompose<ISecurityEventTokenValidator>("clean")
            .Select(step => step.GetType()).ToArray();

        Assert.DoesNotContain(typeof(PinIssuerStep), profileSteps);
    }

    /// <summary>
    /// A profile that drops one of ITS critical steps is held to an allowance of ITS OWN: the
    /// options allowances belong to the plain family and must not excuse a named profile.
    /// </summary>
    [Fact]
    public void AProfileDroppingACriticalStep_NeedsItsOwnAllowance()
    {
        var services = Host(options => options.AllowInsecureValidation(
            "An allowance recorded for the PLAIN family; the profile below must not inherit it."));

        services.AddSecurityEventValidationProfile(
            "weakened", profile => profile.Steps.Remove<SignatureStep>());

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
            profile.Steps.Remove<SignatureStep>();
            profile.AllowInsecureValidation("The test weakens its own profile and says so here.");
        });

        Assert.NotNull(services.BuildServiceProvider()
            .GetRequiredKeyedService<ISecurityEventTokenValidator>("weakened"));
    }

    /// <summary>
    /// A critical step declared FOR a profile binds to that profile alone - the plain family's
    /// guard must not start demanding another consumer's steps.
    /// </summary>
    [Fact]
    public void AProfileScopedCriticalStep_DoesNotBindThePlainFamily()
    {
        var services = Host();

        services.AddSecurityEventValidationProfile("strict", profile =>
        {
            profile.Steps.AddLast(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ProfileCriticalStep>());
            profile.AddCriticalStep<ProfileCriticalStep>();
        });

        // The plain family lacks ProfileCriticalStep and must still construct without any
        // allowance: the declaration was scoped to "strict".
        Assert.NotNull(services.BuildServiceProvider()
            .GetRequiredService<ISecurityEventTokenValidator>());
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
        services.AddSecurityEventValidationProfile("taken");

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
