// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.Utils;

/// <summary>
/// Extension methods for <see cref="IDistributedCache"/> providing atomic operations.
/// </summary>
public static class DistributedCacheExtensions
{
	/// <summary>
	/// Marker value stored by <see cref="TryAddAsync"/>: presence of the key is the fact, the
	/// stored bytes carry no information of their own.
	/// </summary>
	private static readonly byte[] PresenceMarker = [1];

	/// <summary>
	/// Floor applied to the time-to-live requested from <see cref="TryAddAsync"/>.
	/// <see cref="DistributedCacheEntryOptions.AbsoluteExpirationRelativeToNow"/> rejects a zero or
	/// negative value outright, and a caller-side clock skew can legitimately produce one; the floor
	/// keeps a skewed caller marking instead of throwing, at the cost of remembering a few seconds
	/// longer than asked.
	/// </summary>
	private static readonly TimeSpan MinimumTimeToLive = TimeSpan.FromSeconds(10);

	/// <summary>
	/// Marks a key as present unless it already is, telling a first call from a repeat: the
	/// add-if-absent primitive replay caches and other "seen before?" checks are built on.
	/// </summary>
	/// <remarks>
	/// <para>
	/// <strong>Not atomic:</strong> <see cref="IDistributedCache"/> exposes only Get + Set, no
	/// compare-and-set primitive, so two concurrent callers of the same key can both observe a miss
	/// before either writes and both hear "new". The race window is bounded by the cache round-trip,
	/// which makes the duplicate-detection guarantee probabilistic rather than strict. Callers whose
	/// domain needs strict exactly-once use a backend-aware primitive instead - for replay prevention
	/// that is a <c>ReplayCacheBase</c> over the store's own conditional write (Redis
	/// <c>SET ... NX PX</c>, SQL <c>INSERT ... ON CONFLICT DO NOTHING</c>).
	/// </para>
	/// <para>
	/// The entry stores an opaque marker; only the key's presence carries meaning. The requested
	/// time-to-live is floored to a small positive minimum so a value the cache would reject or
	/// discard immediately still records the sighting.
	/// </para>
	/// </remarks>
	/// <param name="cache">The distributed cache instance.</param>
	/// <param name="key">The key whose first sighting is being recorded.</param>
	/// <param name="timeToLive">How long the sighting is remembered.</param>
	/// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
	/// <returns>
	/// A task containing true when the key was absent and is now marked; false when it was
	/// already present.
	/// </returns>
	public static async Task<bool> TryAddAsync(
		this IDistributedCache cache,
		string key,
		TimeSpan timeToLive,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(cache);
		ArgumentNullException.ThrowIfNull(key);

		if (await cache.GetAsync(key, cancellationToken) != null)
		{
			return false;
		}

		if (timeToLive < MinimumTimeToLive)
		{
			timeToLive = MinimumTimeToLive;
		}

		await cache.SetAsync(
			key,
			PresenceMarker,
			new () { AbsoluteExpirationRelativeToNow = timeToLive },
			cancellationToken);

		return true;
	}

	/// <summary>
	/// Reads a value and removes it, both under one hold of the per-key gate, for a cache with no native
	/// primitive of its own. This is NOT the equivalent of Redis GETDEL. The gate holds out other
	/// REDEMPTIONS of the key and nothing else, so a plain write landing between the read and the removal
	/// is destroyed by this caller while it is handed the earlier bytes - and that is only one of the ways
	/// the two differ. AT MOST one caller is handed the value when nothing writes the key, and none may be.
	/// Read the remarks before relying on it.
	/// </summary>
	/// <remarks>
	/// <para><strong>Atomicity Protocol:</strong></para>
	/// <list type="number">
	///   <item><term>Step 1:</term> Take the per-key gate, so no other redemption of this key runs in
	///   this process while the rest happens</item>
	///   <item><term>Step 2:</term> Read the value, and give up if there is none</item>
	///   <item><term>Step 3:</term> Run the removal protocol of <see cref="TryRemoveAsync"/> under the
	///   same hold</item>
	/// </list>
	/// <para>
	/// <strong>How it provides atomicity:</strong> the removal reports itself under the same condition
	/// <see cref="TryRemoveAsync"/> states, and the read is inside the same hold of the gate rather than
	/// in front of it.
	/// </para>
	/// <para>
	/// <strong>What the read's placement buys, and what it does not.</strong> The bytes handed back are
	/// the bytes at the key when this caller got IN - not the ones there before it waited, and that wait
	/// is as long as another caller's whole redemption. What is still open is narrower and real: a writer
	/// that takes no gate can land between the read and the removal, so this caller destroys that write
	/// and is handed the earlier bytes. Nothing in this class closes THAT, and the SERIALIZATION survives
	/// no second process at all - the lock protocol still admits at most one winner across nodes, but
	/// nothing there holds the read and the removal together. A store whose own primitive returns the
	/// removed value closes both, and issue 435 tracks it.
	/// </para>
	/// <para>
	/// <strong>Lock timeout:</strong> the claim auto-expires after the specified timeout (5 seconds by
	/// default), so a process that crashes mid-protocol does not leave the key claimed forever. It also
	/// means a caller slower than the timeout loses its own claim: see <see cref="TryRemoveAsync"/>.
	/// </para>
	/// <para>
	/// <strong>Performance:</strong> up to six cache operations - one read, and up to five in the removal
	/// protocol - so it has higher latency than a store's own atomic primitive, and works with any
	/// IDistributedCache in exchange. All of them inside the gate, so a contended key serializes for the
	/// whole of that rather than for the removal alone.
	/// </para>
	/// </remarks>
	/// <param name="cache">The distributed cache instance.</param>
	/// <param name="key">The key of the value to retrieve and remove.</param>
	/// <param name="lockTimeout">Duration after which the lock expires, 5 seconds if null.</param>
	/// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
	/// <returns>
	/// A task that completes when the operation finishes, containing the value read under this caller's
	/// own hold of the gate, when its claim was still in the store afterwards. Null otherwise, which does
	/// NOT mean somebody else took it: see <see cref="TryRemoveAsync"/>, whose remarks carry the
	/// condition; this method adds nothing to it beyond returning the value. What the placement of the
	/// read does and does not settle is in the remarks.
	/// </returns>
	public static Task<byte[]?> TryGetAndRemoveAsync(
		this IDistributedCache cache,
		string key,
		TimeSpan? lockTimeout = null,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(cache);
		ArgumentNullException.ThrowIfNull(key);

		// Read and removal under ONE hold of the gate, so the bytes handed back are the bytes that were at
		// the key when this caller got in - rather than the ones that were there before it waited, which is
		// a wait as long as another caller's whole redemption. RemoveUnderGateAsync is called directly
		// instead of TryRemoveAsync, because taking the gate twice on one key deadlocks a caller against
		// itself.
		return UnderGateAsync(key, cancellationToken, async () =>
		{
			var valueData = await cache.GetAsync(key, cancellationToken);
			if (valueData == null)
			{
				return null;
			}

			// Not necessarily somebody else when this is false: see TryRemoveAsync's remarks.
			return await RemoveUnderGateAsync(cache, key, lockTimeout, cancellationToken)
				? valueData
				: null;
		});
	}

	/// <summary>
	/// Atomically attempts to remove a value from the distributed cache.
	/// Uses a lock-based protocol to ensure atomic removal semantics, preventing race conditions
	/// where multiple threads attempt to remove the same key concurrently.
	/// </summary>
	/// <remarks>
	/// <para><strong>Atomicity Protocol:</strong></para>
	/// <list type="number">
	///   <item><term>Step 1:</term> Write a unique claim token to the fully-qualified lock key</item>
	///   <item><term>Step 2:</term> Check the value is there at all, and give up early if it is not</item>
	///   <item><term>Step 3:</term> Remove the value from cache</item>
	///   <item><term>Step 4:</term> Read back the claim token and verify it is still ours</item>
	///   <item><term>Step 5:</term> Clean up the lock key</item>
	/// </list>
	/// <para>
	/// <strong>How it provides atomicity:</strong> a caller reports the removal as its own only when its
	/// own claim is still in the store at the end of the protocol. What that condition does and does not
	/// buy is spelled out below.
	/// </para>
	/// <para>
	/// <strong>Use Case:</strong> This method is useful when you need to atomically remove a value without
	/// retrieving it (unlike <see cref="TryGetAndRemoveAsync"/>). For example, in the Device Authorization
	/// Grant flow when a user denies authorization, you only need confirmation that the request was removed,
	/// not the request data itself.
	/// </para>
	/// <para>
	/// <strong>What the protocol decides:</strong> a caller is told it took the value only when the
	/// protocol runs to the end AND finds its own lock token still in the store.
	/// </para>
	/// <para>
	/// That is the whole contract, and it is deliberately not followed by a count of what can go wrong.
	/// Such a list is not closable - the token can be overwritten, it can expire while a cache call
	/// stalls, and the store calls after the removal can fail, and there is no argument that those are
	/// all. What the tests carry instead, each dying when its fact stops holding:
	/// <c>TryRemoveAsync_TheLockExpiresMidProtocol_OneCallerAloneLosesTheValue</c> for a removal with
	/// nobody told, on one node with no competitor, and
	/// <c>TryRemoveAsync_TheStoreFaultsAfterTheRemoval_TheValueIsGoneAndNobodyIsTold</c> for the same
	/// outcome reached by a fault, where the caller gets an exception rather than an answer at all.
	/// </para>
	/// <para>
	/// <strong>What the check does NOT give you.</strong> It does not make this a take-once: the gate
	/// serializes callers within one process, so a competitor cannot overwrite another's token HERE, and
	/// nothing about that survives a second node - see below.
	/// </para>
	/// <para>
	/// <strong>Across processes even the overwrite reopens.</strong> Two nodes redeeming the same key at
	/// the same moment can end with the value removed and neither told it took it, because the lock
	/// protocol is
	/// assembled from <c>Get</c>, <c>Set</c> and <c>Remove</c> as three separate operations and there is a
	/// window between any two of them. A take-once needs one indivisible read-modify-write, and this
	/// interface exposes none: no compare-and-swap, no set-if-absent, no delete-returning-value.
	/// </para>
	/// <para>
	/// <strong>A deployment on several nodes that cannot afford that</strong> supplies its own storage and
	/// reaches for the primitive its store already has. No new API is needed for that:
	/// <c>IDeviceAuthorizationStorage</c>, <c>IBackChannelRequestStorage</c> and <c>IEntityStorage</c> are
	/// public and registered with <c>TryAddSingleton</c>, so a host's own registration wins. Which
	/// primitive to reach for depends on the store, which is why it cannot be chosen here:
	/// </para>
	/// <list type="bullet">
	///   <item>Redis 6.2 and later: <c>GETDEL key</c>, one command, which returns the value to exactly one
	///   caller and deletes it. Earlier versions get the same effect from a two-line <c>EVAL</c> script,
	///   since Redis runs a script indivisibly. Both are for a storage of your own: they read a STRING,
	///   and the <c>IDistributedCache</c> implementation for Redis keeps each entry as a hash whose value
	///   sits in a field, so pointed at these keys they answer <c>WRONGTYPE</c>.</item>
	///   <item>PostgreSQL: <c>DELETE FROM ... WHERE key = $1 RETURNING value</c>. The row lock picks the
	///   winner, and at the default isolation level the loser returns no rows; under REPEATABLE READ or
	///   SERIALIZABLE it fails to serialize instead, which is the same answer through an exception.</item>
	///   <item>SQL Server: <c>DELETE ... OUTPUT deleted.value</c>, the same shape.</item>
	///   <item>Oracle: <c>DELETE ... RETURNING value INTO :out</c>. Oracle documents the RETURNING INTO
	///   clause as belonging to DELETE among others, and for a DELETE it yields the pre-deletion value.</item>
	/// </list>
	/// <para>
	/// <strong>Lock timeout:</strong> Locks auto-expire after the specified timeout (default 5 seconds)
	/// to prevent orphaned locks if a process crashes between writing the lock token and cleaning it up.
	/// </para>
	/// </remarks>
	/// <param name="cache">The distributed cache instance.</param>
	/// <param name="key">The key of the value to remove.</param>
	/// <param name="lockTimeout">Duration after which the lock expires, 5 seconds if null.</param>
	/// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
	/// <returns>
	/// A task that completes when the operation finishes, containing true when the value was removed by
	/// this caller AND its own lock token was still in the store afterwards. False otherwise - which covers
	/// the key not being there, another caller having taken it, and the case where the value is gone and
	/// nobody can be told they took it. That last one does not need a second node: see the remarks. A
	/// store fault after the removal raises rather than returning, and loses the value the same way.
	/// </returns>
	public static Task<bool> TryRemoveAsync(
		this IDistributedCache cache,
		string key,
		TimeSpan? lockTimeout = null,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(cache);
		ArgumentNullException.ThrowIfNull(key);

		// Redemptions of the SAME key are serialized within this process, so the protocol below never runs
		// concurrently against itself here and no caller can overwrite another's lock token. That is one of
		// the three ways a value is lost with nobody told; the other two - an expiring lock and a store
		// fault after the removal - need no competitor and are untouched by this. Callers on different keys
		// never meet: the gate exists only while a call is in flight and is discarded with the last one
		// out.
		//
		// Both entry points hand their whole protocol to UnderGateAsync, which is the only place the gate
		// is taken. Calling one public method from the other would take it twice on one key and deadlock a
		// caller against itself, which is why the shared body is private rather than the public sibling.
		return UnderGateAsync(
			key, cancellationToken, () => RemoveUnderGateAsync(cache, key, lockTimeout, cancellationToken));
	}

	/// <summary>
	/// Runs one redemption of a key with every other redemption of that key in this process held out.
	/// </summary>
	/// <remarks>
	/// The only place the gate is taken. Both entry points hand their whole protocol in -
	/// <see cref="TryGetAndRemoveAsync"/> its read and its removal together - and neither body calls the
	/// other's public method, which is what a body taking the gate twice on one key would do.
	/// <para>
	/// What that buys is bounded by what the gate holds out, which is other REDEMPTIONS and nothing else.
	/// A plain <c>SetAsync</c> or <c>RemoveAsync</c> on the same key takes nothing and is not held out at
	/// all, so one landing between the read and the removal is destroyed by this caller while it is handed
	/// the earlier bytes - or turns a live value into a refusal with nobody told. The live example in this
	/// repository is the back-channel request, updated on completion from four handlers on the key this
	/// protocol redeems, by an approval genuinely concurrent with a token-endpoint poll.
	/// <para>
	/// So the value returned is the value at the key when this caller got IN, which is a narrower window
	/// than before and not a guarantee that it is the value removed.
	/// </para>
	/// </para>
	/// </remarks>
	private static async Task<T> UnderGateAsync<T>(
		string key,
		CancellationToken cancellationToken,
		Func<Task<T>> body)
	{
		var gate = RentGate(key);
		try
		{
			await gate.WaitAsync(cancellationToken);
			try
			{
				return await body();
			}
			finally
			{
				gate.Release();
			}
		}
		finally
		{
			ReturnGate(key);
		}
	}

	/// <summary>
	/// One gate per key, alive only while a redemption of that key is in flight.
	/// </summary>
	/// <remarks>
	/// Retired on the way out, unlike the per-stream gate in the security-event outbox, and the difference
	/// is the key space rather than taste: a stream is a long-lived entity and its gates are bounded by how
	/// many exist, while these are keyed by the code being redeemed, so a table that never forgets would
	/// grow by one entry for every authorization the deployment ever issues.
	/// </remarks>
	/// <remarks>
	/// Internal rather than private so the test that proves it is emptied can name it and be carried
	/// through a rename by the compiler. Read-only from outside this class either way.
	/// </remarks>
	internal static readonly Dictionary<string, GateEntry> Gates = new(StringComparer.Ordinal);

	internal sealed class GateEntry
	{
		public readonly SemaphoreSlim Gate = new(1, 1);
		public int Waiters;
	}

	private static SemaphoreSlim RentGate(string key)
	{
		lock (Gates)
		{
			if (!Gates.TryGetValue(key, out var entry))
			{
				entry = new GateEntry();
				Gates[key] = entry;
			}

			// Incremented before the caller waits, so nobody else can retire this gate underneath it.
			entry.Waiters++;
			return entry.Gate;
		}
	}

	private static void ReturnGate(string key)
	{
		lock (Gates)
		{
			// Loud rather than defensive: every return is paired with a rent that put the entry here, so a
			// miss means the invariant is already broken and swallowing it hides whatever broke it.
			if (!Gates.TryGetValue(key, out var entry))
				throw new InvalidOperationException(
					$"No redemption gate is held. {nameof(RentGate)} and {nameof(ReturnGate)} are paired, so "
					+ "this cannot happen unless one of them was changed.");

			if (--entry.Waiters > 0)
				return;

			// The last caller out retires the gate, which is what keeps the table the size of the traffic
			// in flight rather than the size of every key ever redeemed.
			Gates.Remove(key);
			entry.Gate.Dispose();
		}
	}

	private static async Task<bool> RemoveUnderGateAsync(
		IDistributedCache cache,
		string key,
		TimeSpan? lockTimeout,
		CancellationToken cancellationToken)
	{
		// Use fully qualified type name to avoid collisions with application keys
		var lockKey = $"{nameof(Abblix)}.{nameof(Utils)}.{nameof(DistributedCacheExtensions)}:{nameof(TryRemoveAsync)}:{key}";

		// Write our unique lock token
		var ourLockToken = Guid.NewGuid().ToByteArray();
		await cache.SetAsync(
			lockKey,
			ourLockToken,
			new () { AbsoluteExpirationRelativeToNow = lockTimeout ?? TimeSpan.FromSeconds(5) },
			cancellationToken);

		// The value must still exist at the moment we hold the lock. Without this check a caller whose lock
		// window does not overlap a prior successful removal would still see its own token survive and wrongly
		// report success - breaking exactly-once removal (two token requests both redeeming the same
		// device_code or authorization code). RFC 6749 section 4.1.2 forbids reusing an authorization code; for a
		// device_code no RFC says so, and single use is this codebase's own rule. The documented contract is
		// "false if ... the key didn't exist".
		if (await cache.GetAsync(key, cancellationToken) == null)
		{
			await cache.RemoveAsync(lockKey, cancellationToken); // clean up our lock
			return false;
		}

		// Remove the value
		await cache.RemoveAsync(key, cancellationToken);

		// Verify our lock token survived (last-write-wins check)
		var survivingLockToken = await cache.GetAsync(lockKey, cancellationToken);
		if (survivingLockToken == null || !ourLockToken.SequenceEqual(survivingLockToken))
		{
			// The claim is not ours any more. Do NOT read that as a competitor: it is equally the claim
			// having EXPIRED, which one caller alone reaches, and the value is already gone either way.
			return false;
		}

		// The claim is still ours, which is the whole condition for reporting the removal as this
		// caller's: nothing overwrote it and it did not expire.
		await cache.RemoveAsync(lockKey, cancellationToken); // Cleanup lock
		return true;
	}
}
