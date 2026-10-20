// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Keeps the clients of a session as a numbered list in entity storage, one key per client, under a generation
/// that bounds how long the list lives: at least a retention after the session's last authorization, and at most
/// two.
/// </summary>
/// <remarks>
/// A client is added by claiming the first free position of the current generation, so two authorizations
/// arriving together claim two positions instead of writing one list twice. The list is read from the first
/// position up to the first free one, so no record of a generation is written to expire before the generation
/// itself, and a session whose generation is gone starts a new one instead of writing into positions of the old
/// one that may already have emptied. That holds while the clocks of the server's instances agree: a record
/// written by an instance whose clock is behind the one that last renewed the generation ends earlier by the
/// difference, and a logout in that moment does not reach the clients listed after it.
/// <para>
/// A session goes on under its id when its end user signs in again, so the list is renewed rather than left to
/// expire on the schedule of the first client: the generation and its records are written to last two
/// retentions, and once a retention has passed since the last renewal, the next authorization keeps every one of
/// them two retentions from then. A renewal moves only the expiry of what is still stored, so it never brings
/// back a generation that has ended or writes an old one over the one that replaced it. A renewal of a generation
/// that is replaced while the renewal runs gives the replacement the end it computed, which is earlier than the
/// replacement's own by the time between the two, so the replacement may end that much less than a retention
/// after an authorization.
/// </para>
/// <para>
/// A second key per client says the client is already recorded, so recording a client the session already knows
/// costs four reads, the generation, the marker, the generation again and the note of the last renewal, rather
/// than a search of the list. A renewal costs a read and two extensions per client on top, once a retention.
/// </para>
/// </remarks>
/// <param name="storage">Where the records are claimed and read.</param>
/// <param name="keyFactory">Names the generation, each position, each client and the last renewal.</param>
/// <param name="options">Supplies how long a generation lasts after the session's last authorization.</param>
/// <param name="clock">Supplies the moment a generation's end is measured from.</param>
/// <param name="logger">Reports a session whose list is full.</param>
public partial class SessionClientRegistry(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options,
    TimeProvider clock,
    ILogger<SessionClientRegistry> logger) : ISessionClientRegistry
{
    /// <summary>
    /// How many clients one generation of a session can record.
    /// </summary>
    /// <remarks>
    /// Logout reads every position of the list, and so does every successful authorization, whose response
    /// names the session's clients, so the bound is what one session can cost those reads. A person signs in
    /// to a handful of clients within a session; a list this long is a script registering clients and
    /// authorizing each.
    /// </remarks>
    internal const int MaxClientsPerSession = 1000;

    /// <summary>
    /// How many generations one call writes into before giving up.
    /// </summary>
    /// <remarks>
    /// A write lands in a generation that ended while it was being made only when the generation ends inside
    /// that write, and the generation started to replace it lasts two retentions. A second loss needs a
    /// retention shorter than one write.
    /// </remarks>
    private const int MaxGenerationAttempts = 2;

    /// <inheritdoc />
    public async Task AddClientAsync(
        string sessionId, string clientId, CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; attempt < MaxGenerationAttempts; attempt++)
        {
            var generation = await CurrentOrNewGenerationAsync(sessionId, cancellationToken);
            await RecordAsync(sessionId, generation, clientId, cancellationToken);

            // A generation that ended while the record was being written leaves the client in records no reader
            // reaches any more, so the client is recorded again under the generation that replaces it.
            var current = await storage.GetAsync<Proto.SessionClientsGeneration>(
                keyFactory.SessionClientsGenerationKey(sessionId), false, cancellationToken);

            if (current?.Id == generation.Id)
            {
                await RenewWhenDueAsync(sessionId, current, cancellationToken);
                return;
            }
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<string>> GetClientsAsync(
        string sessionId, CancellationToken cancellationToken = default)
    {
        var generation = await storage.GetAsync<Proto.SessionClientsGeneration>(
            keyFactory.SessionClientsGenerationKey(sessionId), false, cancellationToken);

        if (generation == null)
            return [];

        // A client holds two positions when its authorization stopped between claiming a position and
        // recording that it holds one, and a later authorization of the same client then claimed another.
        var clients = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var position = 1; position <= MaxClientsPerSession; position++)
        {
            var recorded = await storage.GetAsync<Proto.SessionClient>(
                keyFactory.SessionClientKey(sessionId, generation.Id, position), false, cancellationToken);

            if (recorded == null)
                break;

            if (seen.Add(recorded.ClientId))
                clients.Add(recorded.ClientId);
        }

        return clients;
    }

    /// <summary>
    /// When a generation or a record written or renewed now ends: two retentions from now, so that renewing once
    /// a retention keeps the list a whole retention past any authorization.
    /// </summary>
    private DateTimeOffset KeptUntil() => clock.GetUtcNow() + 2 * options.Value.SessionClientsRetention;

    /// <summary>
    /// The session's current generation, started when there is none.
    /// </summary>
    private async Task<Proto.SessionClientsGeneration> CurrentOrNewGenerationAsync(
        string sessionId, CancellationToken cancellationToken)
    {
        var key = keyFactory.SessionClientsGenerationKey(sessionId);
        var current = await storage.GetAsync<Proto.SessionClientsGeneration>(key, false, cancellationToken);
        if (current != null)
            return current;

        var expiresAt = KeptUntil();
        var started = new Proto.SessionClientsGeneration
        {
            Id = Guid.NewGuid().ToString("N"),
            ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt),
        };

        if (await storage.TrySetIfAbsentAsync(
                key, started, new StorageOptions { AbsoluteExpiration = expiresAt }, cancellationToken))
        {
            // A generation just started lasts as long as a renewal would make it
            await NoteRenewedAsync(sessionId, started, expiresAt, cancellationToken);
            return started;
        }

        // Another authorization started the generation first, and its generation is the one to write into.
        // One already gone again leaves this caller its own, which the check after the write then replaces.
        return await storage.GetAsync<Proto.SessionClientsGeneration>(key, false, cancellationToken) ?? started;
    }

    /// <summary>
    /// Records a client in one generation of a session's list, unless it is already recorded there.
    /// </summary>
    private async Task RecordAsync(
        string sessionId,
        Proto.SessionClientsGeneration generation,
        string clientId,
        CancellationToken cancellationToken)
    {
        var markerKey = keyFactory.SessionClientMarkerKey(sessionId, generation.Id, clientId);
        if (await storage.GetAsync<Proto.SessionClient>(markerKey, false, cancellationToken) != null)
            return;

        // The later of the end the generation started with and as long as it can last from now, so no record
        // expires before its generation and leaves a gap the reader stops at. The start's end counts because it
        // was measured on the clock of whichever instance started the generation, which may be ahead of this
        // one. A record outliving its generation is never read again, because a generation's id is never reused.
        var keptUntil = KeptUntil();
        var startedEnd = generation.ExpiresAt.ToDateTimeOffset();
        var storageOptions = new StorageOptions
        {
            AbsoluteExpiration = startedEnd > keptUntil ? startedEnd : keptUntil,
        };
        var record = new Proto.SessionClient { ClientId = clientId };
        var highestTaken = await FindHighestTakenPositionAsync(sessionId, generation.Id, cancellationToken);

        // From there upward, because another caller may have claimed the same position between the search and
        // the claim.
        for (var position = highestTaken + 1; position <= MaxClientsPerSession; position++)
        {
            var positionKey = keyFactory.SessionClientKey(sessionId, generation.Id, position);
            if (!await storage.TrySetIfAbsentAsync(positionKey, record, storageOptions, cancellationToken))
            {
                // Somebody claimed this position first. What they wrote decides whether this client is already
                // on the list.
                var winner = await storage.GetAsync<Proto.SessionClient>(positionKey, false, cancellationToken);
                if (!string.Equals(winner?.ClientId, clientId, StringComparison.Ordinal))
                    continue;
            }

            await storage.SetAsync(markerKey, record, storageOptions, cancellationToken);
            return;
        }

        LogSessionClientsExhausted(sessionId, clientId, MaxClientsPerSession);
    }

    /// <summary>
    /// Keeps a generation and every record in it two retentions from now, when a retention has passed since it
    /// was last renewed.
    /// </summary>
    /// <remarks>
    /// The records are kept longer before the generation, so none expires before the generation that lists
    /// them. The renewal is noted after the attempt to keep the generation longer, so one that stopped half way
    /// is made again by the next authorization rather than waiting a retention.
    /// </remarks>
    private async Task RenewWhenDueAsync(
        string sessionId, Proto.SessionClientsGeneration generation, CancellationToken cancellationToken)
    {
        var renewalKey = keyFactory.SessionClientsRenewalKey(sessionId, generation.Id);
        if (await storage.GetAsync<Proto.SessionClientsGeneration>(renewalKey, false, cancellationToken) != null)
            return;

        var keptUntil = KeptUntil();
        var storageOptions = new StorageOptions { AbsoluteExpiration = keptUntil };
        for (var position = 1; position <= MaxClientsPerSession; position++)
        {
            var positionKey = keyFactory.SessionClientKey(sessionId, generation.Id, position);
            var recorded = await storage.GetAsync<Proto.SessionClient>(positionKey, false, cancellationToken);
            if (recorded == null)
                break;

            await storage.TryExtendAsync(positionKey, storageOptions, cancellationToken);
            await storage.TryExtendAsync(
                keyFactory.SessionClientMarkerKey(sessionId, generation.Id, recorded.ClientId),
                storageOptions,
                cancellationToken);
        }

        await storage.TryExtendAsync(
            keyFactory.SessionClientsGenerationKey(sessionId), storageOptions, cancellationToken);

        await NoteRenewedAsync(sessionId, generation, keptUntil, cancellationToken);
    }

    /// <summary>
    /// Notes that a generation was set to last until <paramref name="keptUntil"/>, so no authorization renews it
    /// until a retention before then.
    /// </summary>
    /// <remarks>
    /// Counted back from that end rather than forward from the moment the note is written, so the time the
    /// writes before it took does not carry the note past the point a renewal is due.
    /// </remarks>
    private Task NoteRenewedAsync(
        string sessionId,
        Proto.SessionClientsGeneration generation,
        DateTimeOffset keptUntil,
        CancellationToken cancellationToken)
        => storage.SetAsync(
            keyFactory.SessionClientsRenewalKey(sessionId, generation.Id),
            generation,
            new StorageOptions { AbsoluteExpiration = keptUntil - options.Value.SessionClientsRetention },
            cancellationToken);

    /// <summary>
    /// The highest position of a generation's list that is taken, found by halving rather than walked, or zero
    /// when none is.
    /// </summary>
    /// <remarks>
    /// Halving answers correctly while the taken positions are one unbroken run from the first. Within a
    /// generation they are, as long as the storage keeps each entry until its expiry: a position is only claimed
    /// above the ones already taken, nothing is removed, and no record is written to expire before its generation.
    /// </remarks>
    private async Task<int> FindHighestTakenPositionAsync(
        string sessionId, string generation, CancellationToken cancellationToken)
    {
        var (low, high) = (1, MaxClientsPerSession);
        var highestTaken = 0;
        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            var recorded = await storage.GetAsync<Proto.SessionClient>(
                keyFactory.SessionClientKey(sessionId, generation, middle), false, cancellationToken);

            if (recorded != null)
            {
                highestTaken = middle;
                low = middle + 1;
            }
            else
            {
                high = middle - 1;
            }
        }

        return highestTaken;
    }

    [LoggerMessage(
        EventId = LogEvents.LogoutNotification.SessionClientRegistry.SessionClientsExhausted,
        Level = LogLevel.Warning,
        Message = "Session {SessionId} already records {Limit} clients, so client {ClientId} is not recorded " +
                  "and will not be notified when the session ends")]
    private partial void LogSessionClientsExhausted(string SessionId, string ClientId, int Limit);
}
