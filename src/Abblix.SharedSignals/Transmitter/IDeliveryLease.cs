// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// A claim on one named piece of delivery work, held for a bounded time, so that among however
/// many transmitter instances are running exactly one performs it.
/// </summary>
/// <remarks>
/// <para>
/// Push delivery reads a stream's queue and empties it as receipts come back, so two instances
/// sweeping one stream both read the same pending SETs and both POST them. RFC 8935 Section 2
/// permits a receiver to be sent the same SET again - "The SET Recipient MUST respond as it would
/// if the SET had not been previously received" - but binds the transmitter the other way: it
/// "should not retransmit a SET unless the SET Transmitter suspects that previous transmissions
/// may have failed due to potentially recoverable errors", and "in all other cases, the SET
/// Transmitter SHOULD NOT retransmit a SET". Instances duplicating each other's work suspect
/// nothing, so this is that SHOULD NOT rather than a matter of wasted traffic.
/// </para>
/// <para>
/// The claim EXPIRES, and that is what separates it from a lock. Expiry is what lets an instance
/// that died mid-pass release its claim without running any code - nothing else would - and it is
/// therefore also the point past which the holder has no claim at all. So a holder must stop the
/// work at its deadline rather than treat the lease as advice: whoever comes next is entitled to
/// start, and two workers overlapping is the very thing being prevented.
/// </para>
/// </remarks>
public interface IDeliveryLease
{
    /// <summary>
    /// Claims <paramref name="name"/> for at most <paramref name="duration"/>.
    /// </summary>
    /// <param name="name">
    /// What is being claimed. Callers scope it themselves, so two kinds of work over one stream do
    /// not collide.</param>
    /// <param name="duration">
    /// How long the claim holds without being released. It bounds two opposite costs: too short
    /// cuts a legitimate pass off and the work is redone next time, too long parks the work for
    /// the remainder after the holder dies. Both are safe, so err on whichever the deployment
    /// minds less.</param>
    /// <param name="cancellationToken">Cancels the I/O a shared implementation performs.</param>
    /// <returns>
    /// A handle that releases the claim when disposed, or null when someone else holds it - which
    /// is an ordinary outcome and not a failure. Releasing is conditional on still holding it, so
    /// a handle disposed after its deadline cannot revoke the claim of whoever took over.
    /// </returns>
    Task<IAsyncDisposable?> TryAcquireAsync(
        string name,
        TimeSpan duration,
        CancellationToken cancellationToken = default);
}
