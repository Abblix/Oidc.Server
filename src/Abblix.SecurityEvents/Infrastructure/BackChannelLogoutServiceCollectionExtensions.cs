// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.BackChannelLogout.Steps;
using Abblix.SecurityEvents.Validation.Steps;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Wires the receiver of OpenID Connect Back-Channel Logout tokens.
/// </summary>
public static class BackChannelLogoutServiceCollectionExtensions
{
    /// <summary>
    /// Registers the receiver of Logout Tokens a provider posts to this application
    /// (OpenID Connect Back-Channel Logout 1.0 Section 2.6), as its own named validation profile.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A Logout Token is a security event token whose profile contradicts the security-event
    /// default on two points, which is what a named profile is for: the default forbids <c>exp</c>
    /// where Section 2.6 requires it, and pins the SET's own type where Section 4.1 forbids
    /// requiring any. Both departures go through the reasoned allowance door, so a host reading
    /// its boot log sees which critical defaults this profile does not carry and why.
    /// </para>
    /// <para>
    /// It sits in this package rather than beside Shared Signals because a logout notification has
    /// no stream: one token, delivered once, from a provider the application already knows. What
    /// it uses is the token and the pipeline, both of which are here.
    /// </para>
    /// <para>
    /// Registering this is the whole opt-in: an application that does not call it has nothing that
    /// accepts a Logout Token. The host still owes two registrations of its own: an
    /// <see cref="ILogoutNotificationSink"/>, because Section 2.7 makes locating and clearing the
    /// sessions the RP's and only the RP knows where it keeps them, and key resolution (for
    /// example <see cref="KeyResolutionServiceCollectionExtensions.AddJwksKeyResolution"/>), because
    /// key trust is deployment knowledge. The request and the response themselves are this package's:
    /// <see cref="BackChannelLogoutHandler"/> reads the posted form and shapes the answer, leaving
    /// a host adapter nothing to decide but how to render it.
    /// </para>
    /// <para>
    /// Step 8, the replay check, is optional in the specification and taken up here, because the
    /// request carrying the token is unauthenticated and the token is a bearer credential in the
    /// plainest sense. The default cache rides the host's <c>IDistributedCache</c>; a deployment
    /// wanting a strictly atomic reservation derives a <c>ReplayCacheBase</c> over its own
    /// store's conditional write and registers that, which TryAdd here then leaves alone.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// What this receiver expects of every Logout Token: the provider as the issuer and this
    /// application's client identifier as the audience. Registered as the shared instance, so a
    /// host pre-registering its own wins.</param>
    public static IServiceCollection AddBackChannelLogoutReceiver(
        this IServiceCollection services,
        BackChannelLogoutValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // First, so a host that forgot the core is told so before anything is registered: the
        // profile registration is what names the missing call.
        services.AddSecurityEventValidationProfileOnce(ValidationProfileKeys.LogoutToken, profile =>
        {
            // The whole order a Logout Token is judged in. Two steps stand where the SET defaults
            // put their own and answer the opposite question - the type rule of Section 4.1, the
            // expiry of Section 2.6 - and three are this kind's alone. Written out rather than as
            // edits to the SET order, because a reader of a profile that departs from the baseline
            // twice should not have to reconstruct the baseline to see what it does.
            profile
                .Use<ParseStep>()
                .Use<ForbidNonceStep>()
                .Use<LogoutTokenTypeStep>()
                .Use<LogoutTokenExpiryStep>()
                .Use<EventsPresenceStep>()
                .Use<JwtIdPresenceStep>()
                .Use<IssuerAllowlistStep>()
                .Use<SignatureStep>()
                .Use<SubjectOrSessionStep>()
                .Use<LogoutEventStep>()
                .Use<AudienceStep>()
                .Use<IssuedAtWindowStep>()
                .Use<TimeOfEventStep>()
                .Use<PayloadDeserializationStep>();

            // Declared beside the listing that adds them, so the two statements cannot drift.
            profile
                .AddCriticalStep<LogoutTokenTypeStep>()
                .AddCriticalStep<LogoutTokenExpiryStep>();

            profile
                .AllowInsecureValidation<TypHeaderStep>(
                    "A Logout Token may carry no 'typ' at all - Section 4.1 says requiring one 'will "
                    + "break most existing deployments' - so the replacement refuses a foreign type "
                    + "and accepts an absent one, which is a lower wall than the SET default's")
                .AllowInsecureValidation<ExpAbsenceStep>(
                    "Back-Channel Logout REQUIRES 'exp' (Section 2.6), inverting the SET default; the "
                    + "replacement polices the same claim with the opposite sign and also refuses one "
                    + "already past");
        });

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.AddDistributedReplayCache();
        services.TryAddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        services.TryAddSingleton<BackChannelLogoutHandler>();

        return services;
    }
}
