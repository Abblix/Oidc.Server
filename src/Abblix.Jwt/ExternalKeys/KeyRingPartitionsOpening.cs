// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Readies the rings of several partitions to serve, each on its own, over one read of the store.
/// </summary>
/// <param name="opening">Readies the ring of each partition.</param>
/// <param name="setup">The partitions kept and the store they share.</param>
internal sealed class KeyRingPartitionsOpening(KeyRingPartitionOpening opening, KeyRingSetup setup)
{
    /// <inheritdoc cref="IKeyRings.OpenAsync"/>
    public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken)
    {
        // Read once for the whole opening: a host's own partitions may be read from a database
        var kept = setup.PartitionsKept.Kept;
        var due = partitions.Where(partition => !opening.IsCurrent(partition, kept)).ToArray();
        var round = new KeyRingStoreRound(setup.Store);
        var failures = new Dictionary<string, Exception>(StringComparer.Ordinal);
        for (var index = 0; index < due.Length; index++)
        {
            if (await FailureOfAsync(due[index], round, cancellationToken) is not { } failure)
                continue;

            failures[due[index]] = failure;
            if (cancellationToken.IsCancellationRequested)
            {
                // What was opened stays open, so the next opening goes on from where this one was stopped
                foreach (var unreached in due.Skip(index + 1))
                    failures[unreached] = failure;

                break;
            }
        }

        return failures;
    }

    /// <summary>
    /// Why opening <paramref name="partition"/> failed, or null when it opened.
    /// </summary>
    private async Task<Exception?> FailureOfAsync(
        string partition,
        KeyRingStoreRound round,
        CancellationToken cancellationToken)
    {
        try
        {
            await opening.OpenAsync(partition, round, cancellationToken);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }
}
