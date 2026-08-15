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
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// The decorator over the composed validator that judges the composed RESULT: whichever door
/// edited the profile, a composition lacking a security-critical default either carries a
/// reasoned acknowledgement - logged, so the weakening is visible in the boot log - or fails
/// construction naming what is missing. At validation time it is a pure pass-through.
/// </summary>
/// <remarks>
/// Guarding the result rather than any editing API is what puts every editing door inside its
/// reach: the old pipeline builder watched its own doors, and the composition cursor walked past
/// them. What remains outside is wholesale replacement of the singular registration, which
/// replaces this guard along with the profile - a visible takeover, not an edit. The check runs
/// once, when the singleton is first resolved, which is the earliest moment the final
/// composition exists to inspect.
/// </remarks>
internal sealed partial class InsecureValidationGuard : ISecurityEventTokenValidator
{
    private readonly ISecurityEventTokenValidator _inner;

    public InsecureValidationGuard(
        ISecurityEventTokenValidator inner,
        IServiceProvider serviceProvider,
        ILogger<InsecureValidationGuard> logger,
        ValidationProfileIdentity profile)
    {
        _inner = inner;

        // Ask the family what it holds, and let it answer for its own arrangement - composed or not, behind
        // whatever composite. The key here is the profile's own identity, supplied by the registration that
        // decorated this guard over that very family - never a guess that could go stale and answer empty.
        var memberTypes = serviceProvider
            .Decompose<ISecurityEventTokenValidator>(profile.Key)
            .Select(step => step.GetType())
            .ToHashSet();

        // Every package that contributes a step carrying the marker declares it keyed to its profile, so
        // each profile is judged only by the declarations meant for it: a global set would make this guard
        // demand another consumer's steps of a profile that was never supposed to carry them.
        var missing = serviceProvider
            .GetKeyedServices<CriticalValidationStep>(profile.Key)
            .Select(step => step.StepType)
            .Distinct()
            .Where(critical => !memberTypes.Contains(critical))
            .ToArray();

        if (missing.Length == 0)
        {
            return;
        }

        // Each missing step needs an allowance naming IT. A count would let one reasoned departure
        // excuse every other, including a critical default added to the core long after this
        // profile was written and read by nobody since.
        var excused = profile.Allowances.ToDictionary(allowance => allowance.Step, allowance => allowance.Reason);

        var unexcused = missing.Where(critical => !excused.ContainsKey(critical)).ToArray();
        if (unexcused.Length > 0)
        {
            var unexcusedNames = string.Join(", ", unexcused.Select(type => type.Name));
            throw new InvalidOperationException(
                $"The validation profile '{profile.Key}' lacks security-critical steps ({unexcusedNames}) "
                + $"with no allowance naming them; call {nameof(ValidationProfile)}."
                + $"{nameof(ValidationProfile.AllowInsecureValidation)}<TStep>(reason) on the profile for "
                + "each one, so the weakening is a visible decision instead of an accident.");
        }

        foreach (var critical in missing)
        {
            LogInsecureValidationAllowance(logger, critical.Name, excused[critical]);
        }
    }

    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
        => _inner.ValidateAsync(context, cancellationToken);

    [LoggerMessage(
        EventId = LogEvents.Composition.InsecureProfileAllowance,
        Level = LogLevel.Warning,
        Message = "The validation profile lacks security-critical default steps ({MissingSteps}) "
            + "under an explicit allowance: {Allowance}")]
    private static partial void LogInsecureValidationAllowance(
        ILogger logger,
        string missingSteps,
        string allowance);
}
