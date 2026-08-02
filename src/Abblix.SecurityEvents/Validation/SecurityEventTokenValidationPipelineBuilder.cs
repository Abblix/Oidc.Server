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

using Abblix.SecurityEvents.Validation.Steps;

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// Composes a validation pipeline as an ordered list of step types: the default profile as the
/// base, and a consumer's changes - inserted, replaced, removed steps - as visible operations on
/// it, instead of a forked copy nobody diffs.
/// </summary>
/// <remarks>
/// Removing or replacing a security-critical step demands a prior
/// <see cref="AllowInsecure"/> with a reason. "Temporarily, for a test" is how a disabled
/// signature check reaches production: the reason makes the decision visible at the composition
/// site, survives into <see cref="InsecureAllowances"/> for startup logging, and turns a silent
/// weakening into a grep-able sentence.
/// </remarks>
public sealed class SecurityEventTokenValidationPipelineBuilder
{
    /// <summary>
    /// The default receiver profile, in its required order: parse, then the cheap unverified
    /// rejections, then the signature, then the checks that read trusted claims.
    /// </summary>
    private static readonly Type[] DefaultPipeline =
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
    ];

    private readonly List<Type> _steps = [];
    private readonly List<string> _insecureAllowances = [];
    private string? _pendingInsecureReason;

    /// <summary>
    /// The reasons given for weakening security-critical steps, for the host to log at startup:
    /// a weakened pipeline must be visible in the boot log, not only at the composition site.
    /// </summary>
    public IReadOnlyList<string> InsecureAllowances => _insecureAllowances;

    /// <summary>
    /// Starts from the default receiver profile.
    /// </summary>
    public SecurityEventTokenValidationPipelineBuilder UseDefaultPipeline()
    {
        if (_steps.Count > 0)
        {
            throw new InvalidOperationException(
                "The pipeline already has steps; the default profile is a starting point, not an addition.");
        }

        _steps.AddRange(DefaultPipeline);
        return this;
    }

    /// <summary>
    /// Arms the NEXT <see cref="Remove{TStep}"/> or <see cref="Replace{TExisting, TReplacement}"/>
    /// to touch a security-critical step, with the reason that will be logged at startup.
    /// </summary>
    /// <param name="reason">
    /// Why weakening the pipeline is acceptable here - named concretely enough that reading it in
    /// a production boot log answers the question it raises.</param>
    public SecurityEventTokenValidationPipelineBuilder AllowInsecure(string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);

        if (_pendingInsecureReason is not null)
        {
            throw new InvalidOperationException(
                $"{nameof(AllowInsecure)} is already armed; each allowance covers exactly one operation, "
                + "so one weakening cannot hide behind another's reason.");
        }

        _pendingInsecureReason = reason;
        return this;
    }

    /// <summary>
    /// Inserts a step right after an existing one.
    /// </summary>
    /// <typeparam name="TExisting">The step to insert after.</typeparam>
    /// <typeparam name="TNew">The step to insert.</typeparam>
    public SecurityEventTokenValidationPipelineBuilder InsertAfter<TExisting, TNew>()
        where TExisting : ISecurityEventTokenValidationStep
        where TNew : ISecurityEventTokenValidationStep
    {
        _steps.Insert(IndexOf(typeof(TExisting)) + 1, Unique(typeof(TNew)));
        return this;
    }

    /// <summary>
    /// Replaces a step with another, in place. Replacing a security-critical step requires a
    /// prior <see cref="AllowInsecure"/>: the replacement's adequacy is exactly what nobody has
    /// reviewed.
    /// </summary>
    /// <typeparam name="TExisting">The step to replace.</typeparam>
    /// <typeparam name="TReplacement">The step to put in its place.</typeparam>
    public SecurityEventTokenValidationPipelineBuilder Replace<TExisting, TReplacement>()
        where TExisting : ISecurityEventTokenValidationStep
        where TReplacement : ISecurityEventTokenValidationStep
    {
        DemandAllowanceWhenCritical(typeof(TExisting), nameof(Replace));

        _steps[IndexOf(typeof(TExisting))] = Unique(typeof(TReplacement));
        return this;
    }

    /// <summary>
    /// Removes a step. Removing a security-critical step requires a prior
    /// <see cref="AllowInsecure"/>.
    /// </summary>
    /// <typeparam name="TStep">The step to remove.</typeparam>
    public SecurityEventTokenValidationPipelineBuilder Remove<TStep>()
        where TStep : ISecurityEventTokenValidationStep
    {
        DemandAllowanceWhenCritical(typeof(TStep), nameof(Remove));

        _steps.RemoveAt(IndexOf(typeof(TStep)));
        return this;
    }

    /// <summary>
    /// Materializes the pipeline, resolving each step type through the given factory - the seam
    /// where dependency injection supplies step dependencies without this builder knowing about
    /// containers.
    /// </summary>
    /// <param name="stepFactory">Creates a step instance from its type.</param>
    /// <exception cref="InvalidOperationException">
    /// An <see cref="AllowInsecure"/> was armed but no operation spent it - an allowance nothing
    /// used means the composition does not do what its author believed.</exception>
    public IReadOnlyList<ISecurityEventTokenValidationStep> Build(
        Func<Type, ISecurityEventTokenValidationStep> stepFactory)
    {
        ArgumentNullException.ThrowIfNull(stepFactory);

        if (_pendingInsecureReason is not null)
        {
            throw new InvalidOperationException(
                $"{nameof(AllowInsecure)}(\"{_pendingInsecureReason}\") was not followed by the operation "
                + "it was meant to sanction; the composition does not do what its author believed.");
        }

        return _steps.Select(stepFactory).ToArray();
    }

    private int IndexOf(Type step)
    {
        var index = _steps.IndexOf(step);
        return index >= 0
            ? index
            : throw new InvalidOperationException($"The pipeline holds no step of type {step.Name}.");
    }

    private Type Unique(Type step)
        => !_steps.Contains(step)
            ? step
            : throw new InvalidOperationException(
                $"The pipeline already holds a step of type {step.Name}; a step type appears once, so "
                + "its position and its checks stay singular.");

    private void DemandAllowanceWhenCritical(Type step, string operation)
    {
        if (!typeof(ISecurityCriticalValidationStep).IsAssignableFrom(step))
        {
            return;
        }

        if (_pendingInsecureReason is null)
        {
            throw new InvalidOperationException(
                $"{operation}<{step.Name}> weakens a security-critical check; call "
                + $"{nameof(AllowInsecure)}(reason) first so the decision is visible here and in the "
                + "startup log.");
        }

        _insecureAllowances.Add($"{operation}<{step.Name}>: {_pendingInsecureReason}");
        _pendingInsecureReason = null;
    }
}
