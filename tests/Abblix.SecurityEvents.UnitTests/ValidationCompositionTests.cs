// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the composition contract now that the pipeline is an ordinary composed family: the
/// default order, profile editing through the live cursor, and above all the guard that judges
/// the composed RESULT - a profile lacking a security-critical default demands a reasoned
/// acknowledgement however it came to lack it, which no editing door can bypass.
/// </summary>
public class ValidationCompositionTests
{
    /// <summary>
    /// Stands in for a consumer's profile step; composition tests read types, never run steps.
    /// </summary>
    private sealed class CustomStep : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
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

    // Every family question is asked of a named profile: there is no unnamed family to ask.
    private static Type[] PipelineTypes(IServiceCollection services, string profileKey = "test")
        => services.DecomposeKeyed<ISecurityEventTokenValidator>(profileKey)
            .Select(descriptor => descriptor.ResolveImplementationType()!)
            .ToArray();

    private static ServiceCollection HostWithProfile(Action<ValidationProfile>? configure = null)
    {
        var services = Host();
        // The documented order first, since these cases are about editing it; a profile listing
        // its own steps is the other suite's subject.
        services.AddSecurityEventValidationProfile("test", profile =>
        {
            profile.UseDefaultPipeline();
            configure?.Invoke(profile);
        });
        return services;
    }

    [Fact]
    public void DefaultPipeline_HoldsTheTenStepsInOrder()
    {
        Assert.Equal(
            [
                typeof(ParseStep),
                typeof(TypHeaderStep),
                typeof(ExpAbsenceStep),
                typeof(EventsPresenceStep),
                typeof(JwtIdPresenceStep),
                typeof(IssuerAllowlistStep),
                typeof(SignatureStep),
                typeof(AudienceStep),
                typeof(IssuedAtWindowStep),
                typeof(PayloadDeserializationStep),
            ],
            PipelineTypes(HostWithProfile()));
    }

    [Fact]
    public void PreRegisteredEventTypeRegistry_IsRefusedNamingTheOptionsDoor()
    {
        // Two registry instances would split the registrations: the container would serve one
        // while the options filled the other, and every event registered through the options
        // would silently deserialize as unknown. The refusal happens at Add time, where the
        // wiring mistake is one line away from its fix.
        var services = new ServiceCollection();
        services.AddSingleton(new EventTypeRegistry());

        var error = Assert.Throws<InvalidOperationException>(() => services.AddSecurityEvents());

        Assert.Contains(
            $"{nameof(SecurityEventsOptions)}.{nameof(SecurityEventsOptions.Events)}",
            error.Message);
    }

    [Fact]
    public void AddAfter_PlacesTheStepRightAfterItsAnchor()
    {
        var services = HostWithProfile(profile => profile.Steps
            .AddAfter<SignatureStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, CustomStep>()));

        var types = PipelineTypes(services);
        Assert.Equal(Array.IndexOf(types, typeof(SignatureStep)) + 1, Array.IndexOf(types, typeof(CustomStep)));
    }

    [Fact]
    public void RemovingANonCriticalStep_NeedsNoAllowance()
    {
        var services = HostWithProfile(profile => profile.Steps.Remove<AudienceStep>());

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("test"));
    }

    [Theory]
    [InlineData(typeof(TypHeaderStep))]
    [InlineData(typeof(ExpAbsenceStep))]
    [InlineData(typeof(IssuerAllowlistStep))]
    [InlineData(typeof(SignatureStep))]
    public void RemovingACriticalStep_WithoutAnAllowance_FailsValidatorConstruction(Type criticalStep)
    {
        var services = HostWithProfile(profile =>
        {
            var member = profile.Steps.Single(
                descriptor => descriptor.ResolveImplementationType() == criticalStep);
            profile.Steps.Remove(member);
        });

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("test"));

        Assert.Contains(criticalStep.Name, exception.Message);
        Assert.Contains(nameof(ValidationProfile.AllowInsecureValidation), exception.Message);
    }

    [Fact]
    public void RemovingACriticalStep_WithAnAllowance_Constructs()
    {
        var services = HostWithProfile(profile =>
        {
            profile.Steps.Remove<SignatureStep>();
            profile.AllowInsecureValidation<SignatureStep>(
                "integration test profile: tokens are minted unsigned by the test host");
        });

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("test"));
    }

    [Fact]
    public void TheGuard_JudgesTheResult_NotTheDoor()
    {
        // The edit happens AFTER the profile registration, through a cursor reopened by key - an
        // editing door the profile builder does not provide - and the guard still fires, because
        // it inspects what was composed rather than intercepting any API.
        var services = HostWithProfile();
        services.DecomposeKeyed<ISecurityEventTokenValidator>("test")
            .Replace<TypHeaderStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, CustomStep>());

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredKeyedService<ISecurityEventTokenValidator>("test"));

        Assert.Contains(nameof(TypHeaderStep), exception.Message);
    }

    [Fact]
    public void AStrayUnkeyedRegistration_DoesNotEnterAnyProfile()
    {
        // With no unnamed family, an unkeyed validator registration joins nothing: a profile
        // copies the documented defaults, and the only doors into it are its own cursor and key.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Mock.Of<IIssuerKeyResolver>());
        services.AddSingleton<ISecurityEventTokenValidator, CustomStep>();
        services.AddSecurityEvents();
        services.AddSecurityEventValidationProfile("test", profile => profile.UseDefaultPipeline());

        Assert.DoesNotContain(typeof(CustomStep), PipelineTypes(services));
    }
}
