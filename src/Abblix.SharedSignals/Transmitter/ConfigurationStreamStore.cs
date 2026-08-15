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

using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The stream store of a closed deployment: the stream set is the operator's file rather than
/// something receivers create over the network. Right where the receivers are the operator's own
/// products - known in advance, changed by editing configuration.
/// </summary>
/// <remarks>
/// <para>
/// Two things own a stream, and this store keeps them apart. The FILE owns what the stream is -
/// the receiver, the identifier, the audiences, the events, the delivery endpoint, the subjects
/// mode - and the RECEIVER owns what it has since done through the management API: the status it
/// set (SSF 1.0 Section 8.1.2), the subjects it added and removed (Section 8.1.3), and when it
/// last asked for verification (Section 8.1.4.2). The store reconciles the two against a backing
/// store: declared fields are written from the file, receiver-owned fields are carried over from
/// whatever is already there.
/// </para>
/// <para>
/// That split is what makes the file editable and the API meaningful at the same time. Rebuilding
/// the whole state from the file instead - the obvious reading of "configuration is truth" - looks
/// harmless and is not: under <see cref="StreamSubjectsMode.None"/> the subjects a receiver added
/// ARE the stream's coverage, so it would silently unsubscribe the receiver from everything it
/// subscribed to, and Section 9.1 tells that receiver a success says nothing about the
/// transmitter's state, so it never asks and never finds out.
/// </para>
/// <para>
/// A stream in the backing store that the file no longer declares is deleted, because in this
/// store the file IS the stream set: leaving it would keep delivering security events to a
/// receiver the operator removed, which is the failure that matters of the two directions.
/// </para>
/// <para>
/// Which backing store it is decides how far the receiver-owned half reaches. The default is in
/// memory, which is right for one instance; a transmitter running several takes a shared one, or a
/// receiver's pause is honoured by whichever instance took the request while the rest keep
/// delivering - and since the delivery claim moves between instances from pass to pass, the pause
/// appears to be respected intermittently rather than not at all, which is the harder shape to
/// diagnose.
/// </para>
/// </remarks>
public sealed class ConfigurationStreamStore : IStreamStore
{
    /// <summary>
    /// Attempts a contended reconcile makes before giving up on one stream. A retry is needed at
    /// all only while instances start together and write the same declarations at once; the loser
    /// re-reads and writes the same values, so a bound this small cannot cost correctness.
    /// </summary>
    private const int ReconcileAttempts = 3;

    private readonly IStreamStore _streams;
    private readonly IReadOnlyList<StreamState> _declared;

    /// <summary>
    /// Guards the once-per-process reconcile. Process-local ON PURPOSE, and it is not the mutual
    /// exclusion a shared store needs: it stops this instance's own threads reconciling twice,
    /// while several instances doing so concurrently is expected and harmless - they write the
    /// same declared values, and the backing store's own versioning decides the order.
    /// </summary>
    private readonly SemaphoreSlim _reconcileGate = new(1, 1);

    private bool _reconciled;

    /// <summary>
    /// Materializes the configured streams: the transmitter's half - issuer, supported and
    /// delivered sets, the poll endpoint - comes from <paramref name="options"/>, exactly as
    /// the dynamic create would supply it.
    /// </summary>
    /// <param name="options">The deployment's one-time decisions.</param>
    /// <param name="streams">The declared streams.</param>
    /// <param name="backingStore">
    /// Where the reconciled streams live. In memory unless the deployment supplies a shared one,
    /// which is what carries the receiver-owned half between instances.</param>
    /// <exception cref="InvalidOperationException">
    /// Two declarations share a receiver and stream identifier, or a poll stream is declared on
    /// a transmitter with no poll endpoint factory - configuration bugs, refused loudly at
    /// startup rather than surfacing as a broken stream later.</exception>
    public ConfigurationStreamStore(
        SsfTransmitterOptions options,
        IReadOnlyList<ConfiguredStream> streams,
        IStreamStore backingStore)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(streams);

        _streams = backingStore ?? throw new ArgumentNullException(nameof(backingStore));

        // Materialized here rather than during the reconcile, so a configuration bug is a
        // constructor failure at startup rather than a fault on the first request to arrive.
        var declared = new List<StreamState>(streams.Count);
        var seen = new HashSet<(string, string)>();
        foreach (var stream in streams)
        {
            if (!seen.Add((stream.ReceiverId, stream.StreamId)))
            {
                throw new InvalidOperationException(
                    $"The stream '{stream.StreamId}' of receiver '{stream.ReceiverId}' is declared "
                    + "more than once.");
            }

            declared.Add(Materialize(options, stream));
        }

        _declared = declared;
    }

    /// <inheritdoc />
    public async Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        await EnsureReconciledAsync(cancellationToken);
        return await _streams.TryCreateAsync(stream, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<StreamState?> FindAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
    {
        await EnsureReconciledAsync(cancellationToken);
        return await _streams.FindAsync(receiverId, streamId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<StreamState>> ListAsync(
        string receiverId,
        CancellationToken cancellationToken = default)
    {
        await EnsureReconciledAsync(cancellationToken);
        return await _streams.ListAsync(receiverId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
    {
        await EnsureReconciledAsync(cancellationToken);
        return await _streams.ListAllAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        await EnsureReconciledAsync(cancellationToken);
        return await _streams.UpdateAsync(stream, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
    {
        await EnsureReconciledAsync(cancellationToken);
        return await _streams.DeleteAsync(receiverId, streamId, cancellationToken);
    }

    /// <summary>
    /// Brings the backing store in line with the file, once per process, before anything reads it.
    /// </summary>
    /// <remarks>
    /// On first access rather than at construction or from a hosted service, and both alternatives
    /// were rejected for the same reason: neither can promise the reconcile finished before the
    /// first request. A constructor cannot await a shared store without blocking a thread on
    /// startup, and hosted services start in registration order relative to the web host, so a
    /// request can arrive first and read a store the file has not reached - which surfaces as a
    /// receiver's stream briefly missing, and only on some deployments.
    /// </remarks>
    private async Task EnsureReconciledAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _reconciled))
            return;

        await _reconcileGate.WaitAsync(cancellationToken);
        try
        {
            if (_reconciled)
                return;

            foreach (var declared in _declared)
            {
                await ReconcileAsync(declared, cancellationToken);
            }

            await RemoveUndeclaredAsync(cancellationToken);

            Volatile.Write(ref _reconciled, true);
        }
        finally
        {
            _reconcileGate.Release();
        }
    }

    /// <summary>
    /// Writes one declaration over what the backing store holds, keeping the receiver's half.
    /// </summary>
    private async Task ReconcileAsync(StreamState declared, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < ReconcileAttempts; attempt++)
        {
            var stored = await _streams.FindAsync(
                declared.ReceiverId, declared.StreamId, cancellationToken);

            if (stored is null)
            {
                if (await _streams.TryCreateAsync(declared, cancellationToken))
                    return;

                // Another instance created it between the read and the write. Its values are these
                // values, so the only thing left to do is read it back and carry its half over.
                continue;
            }

            var merged = declared with
            {
                // Everything the receiver owns, listed rather than defaulted: a field added to
                // StreamState and forgotten here is silently reset on the next start, and under
                // SubjectsMode.None that costs the stream its whole coverage.
                Status = stored.Status,
                StatusReason = stored.StatusReason,
                AddedSubjects = stored.AddedSubjects,
                RemovedSubjects = stored.RemovedSubjects,
                LastVerificationRequestAt = stored.LastVerificationRequestAt,
                Version = stored.Version,
            };

            if (await _streams.UpdateAsync(merged, cancellationToken))
                return;
        }
    }

    /// <summary>
    /// Drops what the backing store holds and the file does not declare.
    /// </summary>
    /// <remarks>
    /// The file is this store's stream set, so anything else is either a stream the operator
    /// removed or one created through the API, which this store has always treated as lasting only
    /// until the process restarts. Keeping either would go on delivering security events to a
    /// receiver nobody declared.
    /// </remarks>
    private async Task RemoveUndeclaredAsync(CancellationToken cancellationToken)
    {
        var declared = _declared
            .Select(stream => (stream.ReceiverId, stream.StreamId))
            .ToHashSet();

        var undeclared = (await _streams.ListAllAsync(cancellationToken))
            .Where(stored => !declared.Contains((stored.ReceiverId, stored.StreamId)));

        foreach (var stored in undeclared)
        {
            await _streams.DeleteAsync(stored.ReceiverId, stored.StreamId, cancellationToken);
        }
    }

    private static StreamState Materialize(SsfTransmitterOptions options, ConfiguredStream declared)
    {
        StreamDeliveryMethod delivery;
        if (declared.PushEndpointUrl is { } pushEndpoint)
        {
            delivery = new PushDeliveryMethod(pushEndpoint)
            {
                AuthorizationHeader = declared.PushAuthorizationHeader,
            };
        }
        else if (options.PollEndpointFactory is { } pollEndpointOf)
        {
            delivery = new PollDeliveryMethod(pollEndpointOf(declared.StreamId));
        }
        else
        {
            throw new InvalidOperationException(
                $"The stream '{declared.StreamId}' declares no push endpoint and the transmitter "
                + $"offers no poll delivery: set {nameof(ConfiguredStream.PushEndpointUrl)} or "
                + $"{nameof(SsfTransmitterOptions)}.{nameof(SsfTransmitterOptions.PollEndpointFactory)}.");
        }

        return new StreamState
        {
            ReceiverId = declared.ReceiverId,
            SubjectsMode = declared.SubjectsMode,
            Configuration = new StreamConfiguration
            {
                StreamId = declared.StreamId,
                Issuer = options.Issuer,
                Audiences = declared.Audiences.Length > 0 ? declared.Audiences : [declared.ReceiverId],
                EventsSupported = options.EventsSupported is { Count: > 0 } supported ? supported : null,
                EventsRequested = declared.EventsRequested.Length > 0 ? declared.EventsRequested : null,
                EventsDelivered =
                [
                    .. declared.EventsRequested.Where(eventType =>
                        options.EventsSupported.Contains(eventType, StringComparer.Ordinal)),
                ],
                Delivery = delivery,
                MinVerificationInterval = options.MinVerificationInterval,
                Description = declared.Description,
            },
        };
    }
}
