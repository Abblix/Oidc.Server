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

using System.Runtime.CompilerServices;
using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Receiver;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Locks the promise <see cref="ISecurityCriticalValidator"/> makes: a step carrying it does not leave the
/// validation profile without an allowance on record, wherever the step came from. The steps this package
/// contributes come from outside the package that guards them, which is the case the promise used to miss.
/// </summary>
public class CriticalStepDeclarationTests
{
    private static IServiceCollection Receiver()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISecurityEventTokenSigner, FakeSigner>();
        services.AddSingleton<IIssuerKeyResolver, EmptyKeyResolver>();

        return services
            .AddSecurityEvents()
            .AddSsfReceiver(new SharedSignalsValidationOptions());
    }

    // The receiver validates under its own named profile, so the resolve, the removal and the
    // census below all address that profile's family - the plain one no longer carries SSF steps.
    private static ISecurityEventTokenValidator Resolve(IServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredKeyedService<ISecurityEventTokenValidator>(
            SsfReceiverValidation.ProfileKey);
    }

    private static void RemoveStep(IServiceCollection services, Type stepType)
    {
        var family = services.DecomposeKeyed<ISecurityEventTokenValidator>(
            SsfReceiverValidation.ProfileKey);
        family.RemoveAt(family.ToList().FindIndex(
            member => member.ResolveImplementationType() == stepType));
    }

    /// <summary>
    /// The rule that keeps the profile honest as it grows.
    /// </summary>
    /// <remarks>
    /// Every step carrying the marker is checked, so a step added later is covered by this test the day it is
    /// added. If it goes red, a marker-carrying step can now be removed in silence: declare it with
    /// <c>AddCriticalValidationStep</c> beside the registration that contributes it, rather than removing the
    /// marker or narrowing this test.
    /// </remarks>
    [Fact]
    public void NoStepCarryingTheMarkerCanLeaveTheProfileQuietly()
    {
        var criticalSteps = ResolvedCriticalSteps();

        // The two this package contributes are the reason the test exists; naming them keeps an empty set from
        // passing as an all-clear.
        Assert.Contains(typeof(ForbidSubStep), criticalSteps);
        Assert.Contains(typeof(StreamIssuerStep), criticalSteps);

        foreach (var step in criticalSteps)
        {
            var services = Receiver();
            RemoveStep(services, step);

            var exception = Assert.Throws<InvalidOperationException>(() => Resolve(services));
            Assert.Contains(step.Name, exception.Message);
        }
    }

    private static Type[] ResolvedCriticalSteps()
    {
        var services = Receiver();
        using var provider = services.BuildServiceProvider();

        return provider
            .Decompose<ISecurityEventTokenValidator>(SsfReceiverValidation.ProfileKey)
            .Select(step => step.GetType())
            .Where(type => typeof(ISecurityCriticalValidator).IsAssignableFrom(type))
            .ToArray();
    }

    private sealed class FakeSigner : ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
            => Task.FromResult($"signed.{token.JwtId}");
    }

    private sealed class EmptyKeyResolver : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }
}
