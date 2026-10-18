// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Composes the steps of a refresh for one policy (Composition Root): sealing and opening share the key-encryption key
/// lookup, and every step that dates a key reads the same schedule.
/// </summary>
internal sealed class KeyRingRefreshBuilder
{
    /// <summary>
    /// Composes the steps. A constructor body rather than a primary constructor, because each step is built over
    /// the one before it.
    /// </summary>
    /// <param name="serviceProvider">Resolves the services the steps take from the container.</param>
    /// <param name="policy">The rotation policy the steps follow.</param>
    public KeyRingRefreshBuilder(IServiceProvider serviceProvider, MintedKeys policy)
    {
        Schedule = serviceProvider.CreateService<KeyRingSchedule>(Dependency.Override(policy));
        var keyEncryptionKeys = serviceProvider.CreateService<KeyEncryptionKeys>(Dependency.Override(policy));
        var sealing = serviceProvider.CreateService<KeyRingSealing>(
            Dependency.Override(policy), Dependency.Override(keyEncryptionKeys));
        Refresh = new KeyRingRefresh(
            new KeyRingAdoption(sealing, policy, Schedule),
            new KeyRingMinting(sealing, policy, Schedule),
            serviceProvider.CreateService<KeyRingOpening>(Dependency.Override(keyEncryptionKeys)),
            Schedule);
    }

    /// <summary>The clock and the rotation periods every step reads.</summary>
    public KeyRingSchedule Schedule { get; }

    /// <summary>The refresh composed of the steps.</summary>
    public KeyRingRefresh Refresh { get; }
}
