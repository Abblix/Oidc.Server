// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Builds the ring of a partition (Simple Factory), composed of the steps of a refresh.
/// </summary>
internal sealed class KeyRingFactory
{
    private readonly MintedKeys _policy;
    private readonly IKeyRingStore _store;
    private readonly KeyRingRefresh _refresh;
    private readonly KeyRingSchedule _schedule;

    /// <summary>
    /// Builds the steps of a refresh once: they hold no partition of their own, so one refresh serves every ring
    /// built here.
    /// </summary>
    /// <param name="serviceProvider">Resolves the services a ring and its steps take from the container.</param>
    /// <param name="policy">The rotation policy of every ring this factory builds.</param>
    /// <param name="store">The store whose partitions the rings are kept in.</param>
    public KeyRingFactory(IServiceProvider serviceProvider, MintedKeys policy, IKeyRingStore store)
    {
        _policy = policy;
        _store = store;
        var steps = new KeyRingRefreshBuilder(serviceProvider, policy);
        _schedule = steps.Schedule;
        _refresh = steps.Refresh;
    }

    /// <summary>The ring of <paramref name="partition"/>, over that partition of the store.</summary>
    public KeyRing Build(string partition)
    {
        // Adopted keys would be seeded into every ring, so each partition would serve the others' keys, and only
        // the unnamed partition is sure to be the ring's one
        if (partition != KeyRingOptions.DefaultPartition && _policy.AdoptedKeys.Count > 0)
        {
            throw new InvalidOperationException(
                $"Existing keys are adopted into a key ring, and its partition '{partition}' is named, so other " +
                "partitions may come beside it: the same keys would be seeded into each, letting a party trusting " +
                "one partition's keys verify another's tokens. Adopt keys only into the unnamed partition of a " +
                "ring serving one issuer.");
        }

        return new KeyRing(new PartitionedKeyRingStore(_store, partition), _refresh, _schedule);
    }
}
