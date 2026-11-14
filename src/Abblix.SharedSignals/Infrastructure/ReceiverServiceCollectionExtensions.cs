// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SharedSignals.Infrastructure;

/// <summary>
/// Wires the receiver role into a host's service collection, on top of the Security Events core
/// the host has already wired. Every registration here lets a host pre-registration win: the
/// extensions supply defaults, never overrides.
/// </summary>
public static class ReceiverServiceCollectionExtensions
{
    /// <summary>
    /// Registers the receiver role: the push intake handler over the receiver's OWN validation
    /// profile, with the three SSF steps joined in their required positions - the cheap "sub"
    /// rejection among the unverified checks, the stream-issuer binding among the trusted ones,
    /// the critical-members check last.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The receiver validates under its own named profile
    /// (<see cref="ValidationProfileKeys.SecurityEvent"/>) rather than by editing the host's plain
    /// family. The plain family is shared, and another consumer of security event tokens in the
    /// same host - Back-Channel Logout is the live example - shapes it to demands a SET
    /// contradicts outright: its <c>typ</c> replacement refuses everything that is not a logout
    /// token, its <c>exp</c> replacement requires the claim a SET must not carry. Editing the
    /// shared family therefore either breaks that consumer or is broken by it, depending on
    /// registration order, and the loser sees every one of its tokens refused. A named profile
    /// removes the ordering from the outcome: each consumer owns its copy, and this package's
    /// steps and critical declarations bind to this profile alone.
    /// </para>
    /// <para>
    /// The host still owes two registrations of its own: an
    /// <see cref="ISecurityEventSink"/>, because where events
    /// land is the application, and key resolution (for example
    /// <c>AddJwksKeyResolution</c>), because key trust is deployment knowledge. A replay cache
    /// (<c>AddDistributedReplayCache</c>) is optional and picked up when present.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// What this receiver expects of every token; registered as the shared instance, so a host
    /// pre-registering its own <see cref="SharedSignalsValidationOptions"/> wins.</param>
    public static IServiceCollection AddSharedSignalsReceiver(
        this IServiceCollection services,
        SharedSignalsValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        SharedSignalsRegistration.RequireSecurityEvents(services, nameof(AddSharedSignalsReceiver));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.AddSharedSignalsEventTypes();

        // Every call this receiver makes outward goes through the factory, so one line of a host's
        // - ConfigureHttpClientDefaults, or a call naming one of the published transport names -
        // reaches all of them. A client the library merely ACCEPTS an HttpClient for is not on
        // that path: the host would have to build and wire it, and nothing would say so.
        services.AddHttpClient<PollClient>();
        services.AddHttpClient<TransmitterConfigurationClient>();

        // Named rather than typed, because the client it feeds is paired with the transmitter's
        // metadata, which a receiver learns at run time - so the factory builds it, not the
        // container.
        services.AddHttpClient(StreamManagementTransport.HttpClientName);
        services.TryAddSingleton<StreamManagementClientFactory>();

        // The push intake is RFC 8935's, not this framework's, so it takes the profile, the
        // expectations and the sink as parameters. Bound here because only this call knows which
        // profile is meant - and a keyed-service attribute could not say it, since an attribute
        // takes a compile-time constant while the key belongs to the registration.
        services.TryAddSingleton(provider => provider.CreateService<PushDeliveryHandler>(
            Dependency.Override<ISecurityEventTokenValidator>(
                serviceProvider => serviceProvider.GetRequiredKeyedService<ISecurityEventTokenValidator>(
                    ValidationProfileKeys.SecurityEvent)),
            // Resolved, not captured. TryAddSingleton above lets a host's own instance win, so
            // closing over the argument would judge tokens by the placeholder while every other
            // reader of the container saw the host's - one value with two sources, disagreeing
            // silently.
            Dependency.Override<SecurityEventTokenValidationOptions>(
                serviceProvider => serviceProvider.GetRequiredService<SharedSignalsValidationOptions>())));

        services.AddSecurityEventValidationProfileOnce(ValidationProfileKeys.SecurityEvent, profile =>
        {
            // The whole order a SET is judged in, written out: parse, then the rejections cheap
            // enough to make before any signature work, then the signature, then the checks that
            // read claims the issuer has now vouched for. The three SSF steps sit where that order
            // puts them - "sub" among the cheap ones, the stream issuer beside the audience it
            // qualifies, the critical members last, once payloads are typed.
            profile
                .Use<ParseStep>()
                .Use<TypHeaderStep>()
                .Use<ExpAbsenceStep>()
                .Use<ForbidSubStep>()
                .Use<EventsPresenceStep>()
                .Use<JwtIdPresenceStep>()
                .Use<IssuerAllowlistStep>()
                .Use<SignatureStep>()
                .Use<AudienceStep>()
                .Use<StreamIssuerStep>()
                .Use<IssuedAtWindowStep>()
                .Use<TimeOfEventStep>()
                .Use<PayloadDeserializationStep>()
                .Use<CriticalSubjectMembersStep>();

            // Two of the three carry the security-critical marker, and the marker only binds a
            // profile that knows about them: declared here, beside the listing that adds them, so
            // the two statements cannot drift apart.
            profile
                .AddCriticalStep<ForbidSubStep>()
                .AddCriticalStep<StreamIssuerStep>();
        });

        return services;
    }
}
