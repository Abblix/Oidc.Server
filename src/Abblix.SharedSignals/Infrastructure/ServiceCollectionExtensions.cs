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
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.BackChannelLogout;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SharedSignals.Infrastructure;

/// <summary>
/// Wires the package into a host's service collection, one call per role. Both build on the
/// Security Events core the host has already wired - key trust and signing are deployment
/// knowledge that belongs to that call - and every registration here lets a host
/// pre-registration win: the extensions supply defaults, never overrides.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the transmitter role: the in-memory stream store and outbox as replaceable
    /// defaults, the dispatcher, the management service, the poll endpoint handler, and the
    /// push sender as a typed HTTP client.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// The deployment's one-time decisions; registered as the shared instance, so a host
    /// pre-registering its own <see cref="SsfTransmitterOptions"/> wins.</param>
    public static IServiceCollection AddSsfTransmitter(
        this IServiceCollection services,
        SsfTransmitterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireSecurityEvents(services, nameof(AddSsfTransmitter));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.TryAddSingleton<IStreamStore, InMemoryStreamStore>();
        services.TryAddSingleton<IEventOutbox, InMemoryEventOutbox>();

        // The issuer is a value, not a service, so the dispatcher is built through the factory
        // that overrides exactly that one parameter and resolves the rest - including the
        // sharing policy, which stays optional: a host that registered none runs without one.
        services.TryAddSingleton(provider =>
            provider.CreateService<EventDispatcher>(Dependency.Override(options.Issuer)));

        services.TryAddSingleton<StreamManagementService>();
        services.TryAddSingleton<PollEndpointHandler>();

        // A receiver names the address its stream is delivered to, so that address is input from outside. The
        // policy judges it, and the validating handler puts that judgement on the connection itself - refusing
        // redirects and re-checking the address before every send - so a redirect or a DNS rebinding cannot carry
        // a delivery past the check.
        services.TryAddSingleton<ReceiverAddressPolicy>();
        services.TryAddTransient<ReceiverAddressValidatingHandler>();
        services
            .AddHttpClient<PushDeliverySender>()
            .ConfigurePrimaryHttpMessageHandler<ReceiverAddressValidatingHandler>();

        return services;
    }

    /// <summary>
    /// Registers the receiver role: the push intake handler over the receiver's OWN validation
    /// profile, with the three SSF steps joined in their required positions - the cheap "sub"
    /// rejection among the unverified checks, the stream-issuer binding among the trusted ones,
    /// the critical-members check last.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The receiver validates under its own named profile
    /// (<see cref="SharedSignalsValidationProfiles.SecurityEvent"/>) rather than by editing the host's plain
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
    /// <see cref="Abblix.SharedSignals.Receiver.SecurityEvent.ISecurityEventSink"/>, because where events
    /// land is the application, and key resolution (for example
    /// <c>AddJwksKeyResolution</c>), because key trust is deployment knowledge. A replay cache
    /// (<c>AddDistributedReplayCache</c>) is optional and picked up when present.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// What this receiver expects of every token; registered as the shared instance, so a host
    /// pre-registering its own <see cref="SharedSignalsValidationOptions"/> wins.</param>
    public static IServiceCollection AddSsfReceiver(
        this IServiceCollection services,
        SharedSignalsValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireSecurityEvents(services, nameof(AddSsfReceiver));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.TryAddSingleton<PushDeliveryHandler>();

        services.AddReceiverProfileOnce(SharedSignalsValidationProfiles.SecurityEvent, profile =>
        {
            profile.Steps
                .AddAfter<ExpAbsenceStep>(ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ForbidSubStep>())
                .AddAfter<AudienceStep>(ServiceDescriptor.Singleton<ISecurityEventTokenValidator, StreamIssuerStep>())
                .AddLast(ServiceDescriptor.Singleton<ISecurityEventTokenValidator, CriticalSubjectMembersStep>());

            // Two of the three carry the security-critical marker, and the marker only binds a
            // profile that knows about them: declared here, beside the edit that adds them, so
            // the two statements cannot drift apart.
            profile
                .AddCriticalStep<ForbidSubStep>()
                .AddCriticalStep<StreamIssuerStep>();
        });

        return services;
    }

    /// <summary>
    /// Registers the receiver of Logout Tokens a provider posts to this application
    /// (OpenID Connect Back-Channel Logout 1.0 Section 2.6), as its own named validation profile.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A Logout Token is a security event token whose profile contradicts the security-event
    /// default on two points, which is what a named profile is for: the default forbids <c>exp</c>
    /// where Section 2.6 requires it, and pins the SET's own type where Section 4.1 forbids
    /// requiring any. Both replacements go through the reasoned allowance door, so a host reading
    /// its boot log sees which critical defaults this profile does not carry and why.
    /// </para>
    /// <para>
    /// Registering this is the whole opt-in: an application that does not call it has nothing that
    /// accepts a Logout Token. The host still owes key resolution (for example
    /// <c>AddJwksKeyResolution</c>), because key trust is deployment knowledge, and it owns the
    /// endpoint and the sessions - Section 2.7 makes locating and clearing them the RP's, since
    /// only the RP knows where it keeps them.
    /// </para>
    /// <para>
    /// Step 8, the replay check, is optional in the specification and taken up here, because the
    /// request carrying the token is unauthenticated and the token is a bearer credential in the
    /// plainest sense. The default cache rides the host's <c>IDistributedCache</c>; a deployment
    /// wanting a strictly atomic reservation registers its own <see cref="IReplayCache"/> first.
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
        RequireSecurityEvents(services, nameof(AddBackChannelLogoutReceiver));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.AddDistributedReplayCache();
        services.TryAddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();

        services.AddReceiverProfileOnce(SharedSignalsValidationProfiles.LogoutToken, profile =>
        {
            profile.Steps
                .Replace<TypHeaderStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, LogoutTokenTypeStep>())
                .Replace<ExpAbsenceStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, LogoutTokenExpiryStep>())
                .AddAfter<ParseStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ForbidNonceStep>())
                .AddAfter<SignatureStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, SubjectOrSessionStep>())
                .AddAfter<SubjectOrSessionStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, LogoutEventStep>());

            // Declared beside the edit that adds them, so the two statements cannot drift.
            profile
                .AddCriticalStep<LogoutTokenTypeStep>()
                .AddCriticalStep<LogoutTokenExpiryStep>();

            profile
                .AllowInsecureValidation(
                    "A Logout Token may carry no 'typ' at all - Section 4.1 says requiring one 'will "
                    + "break most existing deployments' - so the replacement refuses a foreign type "
                    + "and accepts an absent one, which is a lower wall than the SET default's")
                .AllowInsecureValidation(
                    "Back-Channel Logout REQUIRES 'exp' (Section 2.6), inverting the SET default; the "
                    + "replacement polices the same claim with the opposite sign and also refuses one "
                    + "already past");
        });

        return services;
    }

    /// <summary>
    /// Declares the transmitter's stream set as configuration: the store of a closed
    /// deployment whose receivers are the operator's own products - nothing to back up,
    /// lifecycle in the operator's file, API mutations ephemeral until restart.
    /// </summary>
    /// <remarks>
    /// Replace rather than TryAdd, deliberately: this call IS the host's explicit choice of
    /// store, so it wins whether it runs before or after
    /// <see cref="AddSsfTransmitter"/>'s in-memory default.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="streams">The declared streams.</param>
    public static IServiceCollection AddSsfConfiguredStreams(
        this IServiceCollection services,
        IReadOnlyList<ConfiguredStream> streams)
    {
        ArgumentNullException.ThrowIfNull(streams);

        services.Replace(ServiceDescriptor.Singleton<IStreamStore>(provider =>
            provider.CreateService<ConfigurationStreamStore>(Dependency.Override(streams))));

        return services;
    }

    /// <summary>
    /// Puts the transmitter's outbox on the host's <c>IDistributedCache</c>, so pending events
    /// survive a process restart when the store behind the cache does. Replace rather than
    /// TryAdd for the same reason as <see cref="AddSsfConfiguredStreams"/>: an explicit choice
    /// wins in any order.
    /// </summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSsfDistributedOutbox(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<IEventOutbox, DistributedCacheEventOutbox>());
        return services;
    }

    /// <summary>
    /// Creates a receiver's named profile, and only on first sight of its key.
    /// </summary>
    /// <remarks>
    /// Re-running a receiver's registration must not double its profile, so the key is looked for
    /// before the profile is created; the profile registration itself refuses a second creation
    /// loudly, which is the right answer for anyone ELSE claiming one of this package's keys.
    /// <para>
    /// One helper for every receiver, because the two answer the same question of the container
    /// and a second copy of the question is what drifts: this package now registers two profiles,
    /// and a third would otherwise arrive with its own spelling of "has this been created yet".
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="profileKey">The key the profile's validator resolves under.</param>
    /// <param name="configure">Shapes the profile: step edits, critical declarations, allowances.</param>
    private static void AddReceiverProfileOnce(
        this IServiceCollection services, string profileKey, Action<ValidationProfile> configure)
    {
        if (services.All(descriptor => !Equals(descriptor.ServiceKey, profileKey)))
            services.AddSecurityEventValidationProfile(profileKey, configure);
    }

    /// <summary>
    /// Both roles build on the Security Events core, and the marker of that call is the one
    /// registration it refuses to duplicate: the event type registry.
    /// </summary>
    private static void RequireSecurityEvents(IServiceCollection services, string caller)
    {
        if (services.All(descriptor => descriptor.ServiceType != typeof(EventTypeRegistry)))
        {
            throw new InvalidOperationException(
                $"{caller} builds on the Security Events core: call AddSecurityEvents(...) first - "
                + "key trust, signing and the validation pipeline are wired there.");
        }
    }
}
