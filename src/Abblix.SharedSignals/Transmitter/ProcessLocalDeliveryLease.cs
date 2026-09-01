// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The lease inside one process, which is the whole of its reach: it excludes the threads of this
/// instance from each other and nothing else. A second instance of the application holds its own
/// dictionary and sees none of these claims, so every instance believes it holds every lease.
/// </summary>
/// <remarks>
/// The name says the boundary because that is the only thing a reader must not get wrong. It is
/// the honest default for a single instance and for tests, and it is the wrong one the moment a
/// deployment scales out - <c>AddSharedSignalsRedisDeliveryLease</c> is the implementation that spans
/// instances, and a deployment already sharing its outbox needs it.
/// </remarks>
/// <param name="timeProvider">The clock the deadlines are read from; a test hands in a fake.</param>
public sealed class ProcessLocalDeliveryLease(TimeProvider timeProvider) : IDeliveryLease
{
    private readonly ConcurrentDictionary<string, Claim> _claims = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<IAsyncDisposable?> TryAcquireAsync(
        string name,
        TimeSpan duration,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(duration, TimeSpan.Zero);
        cancellationToken.ThrowIfCancellationRequested();

        var mine = new Claim(timeProvider.GetUtcNow() + duration);
        Task<IAsyncDisposable?> Acquired() => Task.FromResult<IAsyncDisposable?>(new Handle(this, name, mine));

        while (true)
        {
            if (_claims.TryAdd(name, mine))
            {
                return Acquired();
            }

            if (!_claims.TryGetValue(name, out var held))
            {
                // Released between the two calls, so the name is free again and the add above is
                // worth another attempt. This arm is the only one that can repeat without either
                // taking the claim or conceding it, and it repeats only while someone else keeps
                // releasing - which is progress, not a spin.
                continue;
            }

            if (timeProvider.GetUtcNow() < held.ExpiresAt)
            {
                return Task.FromResult<IAsyncDisposable?>(null);
            }

            // The holder's time has run out. Replacing it is conditional on it still being the
            // claim just read, so of two threads finding the same expired claim exactly one wins
            // and the other comes round to find a live claim and concede.
            if (_claims.TryUpdate(name, mine, held))
            {
                return Acquired();
            }
        }
    }

    /// <summary>
    /// Drops the claim only while it is still the one taken, which is what keeps a handle disposed
    /// after its deadline from revoking the claim of whoever took the name over.
    /// </summary>
    private void Release(string name, Claim claim)
        => _claims.TryRemove(new KeyValuePair<string, Claim>(name, claim));

    /// <summary>
    /// One taking of a name. Identity is the reference, so no two takings are ever equal and the
    /// conditional replace and remove above compare what they mean to compare.
    /// </summary>
    private sealed class Claim(DateTimeOffset expiresAt)
    {
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
    }

    private sealed class Handle(ProcessLocalDeliveryLease lease, string name, Claim claim) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            lease.Release(name, claim);
            return ValueTask.CompletedTask;
        }
    }
}
