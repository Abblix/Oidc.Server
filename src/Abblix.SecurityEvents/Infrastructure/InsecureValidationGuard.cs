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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
        IServiceProvider provider,
        IOptions<SecurityEventsOptions> options,
        ILogger<InsecureValidationGuard> logger)
    {
        _inner = inner;

        // After composition the members live as keyed services under the composite type; a family
        // the host collapsed to a single member never composed, and then the inner validator IS
        // the whole profile.
        var memberTypes = provider
            .GetKeyedServices<ISecurityEventTokenValidator>(typeof(CompositeSecurityEventTokenValidator))
            .Select(member => member.GetType())
            .DefaultIfEmpty(inner.GetType())
            .ToHashSet();

        var missing = ServiceCollectionExtensions.CriticalDefaultSteps
            .Where(critical => !memberTypes.Contains(critical))
            .ToArray();

        if (missing.Length == 0)
        {
            return;
        }

        var missingNames = string.Join(", ", missing.Select(type => type.Name));
        var allowances = options.Value.InsecureValidationAllowances;

        if (allowances.Count == 0)
        {
            throw new InvalidOperationException(
                $"The validation profile lacks security-critical default steps ({missingNames}) and no "
                + $"allowance is on record; call {nameof(SecurityEventsOptions)}."
                + $"{nameof(SecurityEventsOptions.AllowInsecureValidation)}(reason) so the weakening is a "
                + "visible decision instead of an accident.");
        }

        foreach (var allowance in allowances)
        {
            LogInsecureValidationAllowance(logger, missingNames, allowance);
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
