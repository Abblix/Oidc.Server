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
/// that bounds how long the list lives.
/// </summary>
/// <remarks>
/// A client is added by claiming the first free position of the current generation, so two authorizations
/// arriving together claim two positions instead of writing one list twice. The list is read from the first
/// position up to the first free one, so no record of a generation is written to expire before the generation
/// itself, and a session whose generation is gone starts a new one instead of writing into positions of the old
/// one that may already have emptied.
/// <para>
/// A second key per client says the client is already recorded, so an authorization of a client the session
/// already knows costs two reads rather than a walk of the list.
/// </para>
/// </remarks>
/// <param name="storage">Where the records are claimed and read.</param>
/// <param name="keyFactory">Names the generation, each position and each client.</param>
/// <param name="options">Supplies how long a generation lasts.</param>
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
    /// Logout reads every position of the list, and so does each authorization that reports the session's
    /// clients, so the bound is what one session can cost those reads. A person signs in to a handful of clients
    /// within a session; a list this long is a script registering clients and authorizing each.
    /// </remarks>
    internal const int MaxClientsPerSession = 1000;

    /// <summary>
    /// How many generations one call writes into before giving up.
    /// </summary>
    /// <remarks>
    /// A write lands in a generation that ended while it was being made only when the generation ends inside
    /// that write, and the generation started to replace it lasts a whole retention. A second loss needs a
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
                return;
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
    /// The session's current generation, started when there is none.
    /// </summary>
    private async Task<Proto.SessionClientsGeneration> CurrentOrNewGenerationAsync(
        string sessionId, CancellationToken cancellationToken)
    {
        var key = keyFactory.SessionClientsGenerationKey(sessionId);
        var current = await storage.GetAsync<Proto.SessionClientsGeneration>(key, false, cancellationToken);
        if (current != null)
            return current;

        var expiresAt = clock.GetUtcNow() + options.Value.SessionClientsRetention;
        var started = new Proto.SessionClientsGeneration
        {
            Id = Guid.NewGuid().ToString("N"),
            ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt),
        };

        if (await storage.TrySetIfAbsentAsync(
                key, started, new StorageOptions { AbsoluteExpiration = expiresAt }, cancellationToken))
        {
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

        // A record expiring before its generation would leave a gap the reader stops at. A generation this
        // instance's clock already sees as ended is still held by the store, so its records are given a whole
        // retention instead: a record outliving its generation is simply never read again.
        var now = clock.GetUtcNow();
        var generationEnd = generation.ExpiresAt.ToDateTimeOffset();
        var storageOptions = new StorageOptions
        {
            AbsoluteExpiration = generationEnd > now ? generationEnd : now + options.Value.SessionClientsRetention,
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
