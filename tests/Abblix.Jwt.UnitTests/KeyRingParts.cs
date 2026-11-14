// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The parts of a key ring over one store, composed as the container composes them, for a test that hands the ring
/// a store and partitions of its own.
/// </summary>
internal sealed class KeyRingParts
{
    /// <param name="provider">Resolves the clock, the options and the custodian the parts take.</param>
    /// <param name="policy">What every ring mints, and the key-encryption key sealing it.</param>
    /// <param name="store">The store every partition shares.</param>
    /// <param name="kept">The partitions to keep.</param>
    public KeyRingParts(IServiceProvider provider, MintedKeys policy, IKeyRingStore store, IKeyRingPartitions kept)
    {
        var setup = new KeyRingSetup(policy, kept, store);
        Check = new KeyRingStartupCheck(setup, provider.GetRequiredService<IKeyCustodian>());
        Registry = new KeyRingRegistry(new KeyRingFactory(provider, policy, store, Check), setup);
        var opening = new KeyRingPartitionOpening(
            Registry,
            provider.GetRequiredService<IOptions<KeyRingOptions>>(),
            provider.GetRequiredService<TimeProvider>());
        Rings = new KeyRings(
            Registry,
            new KeyRingPartitionsOpening(opening, setup, Check),
            new KeyRingEntriesRemoval(setup));
        Rounds = new KeyRingRounds(Registry, setup, provider.GetRequiredService<IOptions<KeyRingOptions>>());
    }

    public KeyRingRegistry Registry { get; }
    public KeyRings Rings { get; }
    public KeyRingStartupCheck Check { get; }
    public KeyRingRounds Rounds { get; }

    public IKeyRing For(string partition) => Rings.For(partition);

    public KeyRing Ring(string partition) => Registry.Ring(partition);

    public void Close(string partition) => Rings.Close(partition);

    public Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken)
        => Rings.OpenAsync(partitions, cancellationToken);

    public Task<IReadOnlyDictionary<string, Exception>> DeleteAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken)
        => Rings.DeleteAsync(partitions, cancellationToken);

    public void CheckAdoption() => Check.CheckAdoption();

    public Task CheckKeyEncryptionKeyAsync(CancellationToken cancellationToken)
        => Check.CheckKeyEncryptionKeyAsync(cancellationToken);

    public IReadOnlyList<KeyRingPartitionRefresh> BeginRound(bool exceptOpened = false)
        => Rounds.BeginRound(exceptOpened);
}
