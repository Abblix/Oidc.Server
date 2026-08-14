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

    private static Type[] PipelineTypes(IServiceCollection services)
        => services.Decompose<ISecurityEventTokenValidator>()
            .Select(descriptor => descriptor.ResolveImplementationType()!)
            .ToArray();

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
            PipelineTypes(Host()));
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
        var services = Host();
        services.Decompose<ISecurityEventTokenValidator>()
            .AddAfter<SignatureStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, CustomStep>());

        var types = PipelineTypes(services);
        Assert.Equal(Array.IndexOf(types, typeof(SignatureStep)) + 1, Array.IndexOf(types, typeof(CustomStep)));
    }

    [Fact]
    public void RemovingANonCriticalStep_NeedsNoAllowance()
    {
        var services = Host();
        services.Decompose<ISecurityEventTokenValidator>().Remove<AudienceStep>();

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<ISecurityEventTokenValidator>());
    }

    [Theory]
    [InlineData(typeof(TypHeaderStep))]
    [InlineData(typeof(ExpAbsenceStep))]
    [InlineData(typeof(IssuerAllowlistStep))]
    [InlineData(typeof(SignatureStep))]
    public void RemovingACriticalStep_WithoutAnAllowance_FailsValidatorConstruction(Type criticalStep)
    {
        var services = Host();
        var cursor = services.Decompose<ISecurityEventTokenValidator>();
        var member = cursor.Single(descriptor => descriptor.ResolveImplementationType() == criticalStep);
        cursor.Remove(member);

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<ISecurityEventTokenValidator>());

        Assert.Contains(criticalStep.Name, exception.Message);
        Assert.Contains(nameof(SecurityEventsOptions.AllowInsecureValidation), exception.Message);
    }

    [Fact]
    public void RemovingACriticalStep_WithAnAllowance_Constructs()
    {
        var services = Host(options => options.AllowInsecureValidation(
            "integration test profile: tokens are minted unsigned by the test host"));
        services.Decompose<ISecurityEventTokenValidator>().Remove<SignatureStep>();

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<ISecurityEventTokenValidator>());
    }

    [Fact]
    public void TheGuard_JudgesTheResult_NotTheDoor()
    {
        // Replace goes through the cursor's own operation - an editing door this package does
        // not provide - and the guard still fires, because it inspects what was composed rather
        // than intercepting any API.
        var services = Host();
        services.Decompose<ISecurityEventTokenValidator>()
            .Replace<TypHeaderStep>(
                ServiceDescriptor.Singleton<ISecurityEventTokenValidator, CustomStep>());

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<ISecurityEventTokenValidator>());

        Assert.Contains(nameof(TypHeaderStep), exception.Message);
    }

    [Fact]
    public void HostRegisteredStep_BeforeAddSecurityEvents_JoinsTheFamily()
    {
        // The standard family door: a member registered ahead of composition composes in ahead of
        // the defaults, exactly as every composed family in the product line behaves.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Mock.Of<IIssuerKeyResolver>());
        services.AddSingleton<ISecurityEventTokenValidator, CustomStep>();
        services.AddSecurityEvents();

        Assert.Equal(typeof(CustomStep), PipelineTypes(services)[0]);
    }
}
