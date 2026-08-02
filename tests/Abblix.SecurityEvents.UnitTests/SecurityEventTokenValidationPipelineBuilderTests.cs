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

using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the composition rules: the default profile's order, the profile operations, and above all
/// the guard that keeps a security-critical step from being weakened without a reasoned, logged
/// acknowledgement.
/// </summary>
public class SecurityEventTokenValidationPipelineBuilderTests
{
    /// <summary>
    /// Stands in for a consumer's profile step - the sid check of a Back-Channel Logout profile,
    /// say. Composition tests never run steps, so the body is unreachable.
    /// </summary>
    private sealed class CustomStep : ISecurityEventTokenValidationStep
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Composition tests never run steps.");
    }

    /// <summary>
    /// A stand-in replacement for a security-critical step, itself critical - a stricter typ
    /// check, say.
    /// </summary>
    private sealed class CustomCriticalStep : ISecurityCriticalValidationStep
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Composition tests never run steps.");
    }

    private static readonly Dictionary<Type, Func<ISecurityEventTokenValidationStep>> KnownSteps = new()
    {
        [typeof(CustomStep)] = () => new CustomStep(),
        [typeof(CustomCriticalStep)] = () => new CustomCriticalStep(),
    };

    /// <summary>
    /// Resolves composition results into inspectable instances without a container: steps with
    /// dependencies get null - composition tests read types, never run steps.
    /// </summary>
    private static ISecurityEventTokenValidationStep CreateStep(Type type)
        => KnownSteps.TryGetValue(type, out var factory)
            ? factory()
            : (ISecurityEventTokenValidationStep)System.Runtime.CompilerServices.RuntimeHelpers
                .GetUninitializedObject(type);

    private static Type[] TypesOf(IReadOnlyList<ISecurityEventTokenValidationStep> steps)
        => steps.Select(step => step.GetType()).ToArray();

    [Fact]
    public void DefaultPipeline_HoldsTheNineStepsInOrder()
    {
        var steps = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .Build(CreateStep);

        Assert.Equal(
            [
                typeof(ParseStep),
                typeof(TypHeaderStep),
                typeof(ExpAbsenceStep),
                typeof(EventsPresenceStep),
                typeof(IssuerAllowlistStep),
                typeof(SignatureStep),
                typeof(AudienceStep),
                typeof(IssuedAtWindowStep),
                typeof(PayloadDeserializationStep),
            ],
            TypesOf(steps));
    }

    [Fact]
    public void InsertAfter_PlacesTheStepRightAfterItsAnchor()
    {
        var steps = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .InsertAfter<SignatureStep, CustomStep>()
            .Build(CreateStep);

        var types = TypesOf(steps);
        Assert.Equal(Array.IndexOf(types, typeof(SignatureStep)) + 1, Array.IndexOf(types, typeof(CustomStep)));
    }

    [Fact]
    public void Remove_OfANonCriticalStep_NeedsNoAllowance()
    {
        var steps = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .Remove<AudienceStep>()
            .Build(CreateStep);

        Assert.DoesNotContain(typeof(AudienceStep), TypesOf(steps));
    }

    [Theory]
    [InlineData(typeof(TypHeaderStep))]
    [InlineData(typeof(ExpAbsenceStep))]
    [InlineData(typeof(SignatureStep))]
    public void Remove_OfASecurityCriticalStep_DemandsAnAllowance(Type criticalStep)
    {
        var builder = new SecurityEventTokenValidationPipelineBuilder().UseDefaultPipeline();

        var remove = typeof(SecurityEventTokenValidationPipelineBuilder)
            .GetMethod(nameof(SecurityEventTokenValidationPipelineBuilder.Remove))!
            .MakeGenericMethod(criticalStep);

        var exception = Assert.Throws<System.Reflection.TargetInvocationException>(
            () => remove.Invoke(builder, null));

        var inner = Assert.IsType<InvalidOperationException>(exception.InnerException);
        Assert.Contains(nameof(SecurityEventTokenValidationPipelineBuilder.AllowInsecure), inner.Message);
    }

    [Fact]
    public void AllowInsecure_SanctionsExactlyOneOperation_AndIsRecorded()
    {
        var builder = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .AllowInsecure("integration test profile: tokens are minted unsigned by the test host")
            .Remove<SignatureStep>();

        var allowance = Assert.Single(builder.InsecureAllowances);
        Assert.Contains(nameof(SignatureStep), allowance);
        Assert.Contains("integration test profile", allowance);

        // The allowance is spent: the next weakening needs its own reason.
        Assert.Throws<InvalidOperationException>(() => builder.Remove<TypHeaderStep>());
    }

    [Fact]
    public void Replace_OfASecurityCriticalStep_DemandsAnAllowance()
    {
        var builder = new SecurityEventTokenValidationPipelineBuilder().UseDefaultPipeline();

        Assert.Throws<InvalidOperationException>(() => builder.Replace<TypHeaderStep, CustomCriticalStep>());
    }

    [Fact]
    public void Replace_WithAnAllowance_SwapsInPlace()
    {
        var steps = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .AllowInsecure("profile pins its own typ value")
            .Replace<TypHeaderStep, CustomCriticalStep>()
            .Build(CreateStep);

        var types = TypesOf(steps);
        Assert.Equal(1, Array.IndexOf(types, typeof(CustomCriticalStep)));
        Assert.DoesNotContain(typeof(TypHeaderStep), types);
    }

    [Fact]
    public void UnspentAllowance_FailsTheBuild()
    {
        // An allowance nothing used means the composition does not do what its author believed -
        // most likely the operation it was written for was edited away.
        var builder = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .AllowInsecure("orphaned reason");

        Assert.Throws<InvalidOperationException>(() => builder.Build(CreateStep));
    }

    [Fact]
    public void DoubleAllowance_IsRejected()
    {
        var builder = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .AllowInsecure("first");

        Assert.Throws<InvalidOperationException>(() => builder.AllowInsecure("second"));
    }

    [Fact]
    public void InsertingADuplicateStepType_IsRejected()
    {
        var builder = new SecurityEventTokenValidationPipelineBuilder()
            .UseDefaultPipeline()
            .InsertAfter<SignatureStep, CustomStep>();

        Assert.Throws<InvalidOperationException>(() => builder.InsertAfter<ParseStep, CustomStep>());
    }

    [Fact]
    public void OperationsOnAMissingStep_AreRejected()
    {
        var builder = new SecurityEventTokenValidationPipelineBuilder().UseDefaultPipeline();

        Assert.Throws<InvalidOperationException>(() => builder.InsertAfter<CustomStep, CustomCriticalStep>());
        Assert.Throws<InvalidOperationException>(() => builder.Remove<CustomStep>());
    }

    [Fact]
    public void UseDefaultPipeline_Twice_IsRejected()
    {
        var builder = new SecurityEventTokenValidationPipelineBuilder().UseDefaultPipeline();

        Assert.Throws<InvalidOperationException>(() => builder.UseDefaultPipeline());
    }
}
