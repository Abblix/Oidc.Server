// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Keeps the stream store and the outbox the host registered under keys of their own, as what every tenant shares,
/// so their unkeyed registrations can answer with the part of the tenant being served.
/// </summary>
internal static class SharedStores
{
    /// <summary>
    /// Registers the keyed copies of the host's stream store and outbox.
    /// </summary>
    public static void Keep(IServiceCollection services)
    {
        services.DecorateKeyed<IStreamStore, SharedStreamStore>(TenantTransmitters.SharedStoreKey);
        services.DecorateKeyed<IEventOutbox, SharedEventOutbox>(TenantTransmitters.SharedOutboxKey);
    }
}
