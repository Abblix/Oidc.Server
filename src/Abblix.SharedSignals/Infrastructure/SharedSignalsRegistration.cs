// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Events;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.Infrastructure;

/// <summary>
/// What the transmitter and receiver registrations share: the event types this framework defines,
/// and the check that the Security Events core is already wired.
/// </summary>
internal static class SharedSignalsRegistration
{
    /// <summary>
    /// Teaches the event registry the two event types this framework defines for itself.
    /// </summary>
    /// <remarks>
    /// Through the options door, which is the registry's only one: a second registry instance
    /// would silently orphan whatever was registered through the first.
    /// </remarks>
    internal static void AddSharedSignalsEventTypes(this IServiceCollection services)
        => services.Configure<SecurityEventsOptions>(options => options.Events.RegisterSharedSignalsEvents());

    /// <summary>
    /// Both roles build on the Security Events core, and the marker of that call is the one
    /// registration it refuses to duplicate: the event type registry.
    /// </summary>
    internal static void RequireSecurityEvents(IServiceCollection services, string caller)
    {
        if (services.All(descriptor => descriptor.ServiceType != typeof(EventTypeRegistry)))
        {
            throw new InvalidOperationException(
                $"{caller} builds on the Security Events core: call AddSecurityEvents(...) first - "
                + "key trust, signing and the validation pipeline are wired there.");
        }
    }
}
