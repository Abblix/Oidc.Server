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
/// Keeps the clients of a session as a numbered list in entity storage, one key per client.
/// </summary>
/// <remarks>
/// A client is added by claiming the first free position, so two authorizations arriving together claim two
/// positions instead of writing one list twice. The list is read from the first position up to the first free
/// one, so a later record copies the first one's expiry: the records of a session then leave the store
/// together, rather than the first expiring while later ones are still held above the gap it leaves.
/// </remarks>
/// <param name="storage">Where the records are claimed and read.</param>
/// <param name="keyFactory">Names each position.</param>
/// <param name="options">Supplies how long the records are kept.</param>
/// <param name="clock">Supplies the moment the first record's expiry is measured from.</param>
/// <param name="logger">Reports a session whose list is full.</param>
public partial class SessionClientRegistry(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options,
    TimeProvider clock,
    ILogger<SessionClientRegistry> logger) : ISessionClientRegistry
{
    /// <summary>
    /// How many clients one session can record.
    /// </summary>
    /// <remarks>
    /// Each authorization walks the list, so the bound is what one session can cost. A person signs in to a
    /// handful of clients within a session; a list this long is a script registering clients and authorizing
    /// each, and it spends only its own session.
    /// </remarks>
    internal const int MaxClientsPerSession = 1000;

    /// <inheritdoc />
    public async Task AddClientAsync(
        string sessionId, string clientId, CancellationToken cancellationToken = default)
    {
        Timestamp? expiresAt = null;
        for (var position = 1; position <= MaxClientsPerSession; position++)
        {
            var key = keyFactory.SessionClientKey(sessionId, position);
            var recorded = await storage.GetAsync<Proto.SessionClient>(key, false, cancellationToken);
            if (recorded == null)
            {
                // Every later record copies the first one's expiry. One this instance's clock already sees
                // as passed cannot be written, and the records it came from are leaving the store anyway.
                var now = clock.GetUtcNow();
                var inherited = expiresAt?.ToDateTimeOffset();
                var expiry = inherited > now ? inherited.Value : now + options.Value.SessionClientsRetention;

                var record = new Proto.SessionClient
                {
                    ClientId = clientId,
                    ExpiresAt = Timestamp.FromDateTimeOffset(expiry),
                };

                var storageOptions = new StorageOptions { AbsoluteExpiration = expiry };
                if (await storage.TrySetIfAbsentAsync(key, record, storageOptions, cancellationToken))
                    return;

                // Somebody claimed this position first. What they wrote decides whether this client is
                // already on the list; if it is already gone, the next position is asked instead.
                recorded = await storage.GetAsync<Proto.SessionClient>(key, false, cancellationToken);
                if (recorded == null)
                    continue;
            }

            if (string.Equals(recorded.ClientId, clientId, StringComparison.Ordinal))
                return;

            expiresAt ??= recorded.ExpiresAt;
        }

        LogSessionClientsExhausted(sessionId, clientId, MaxClientsPerSession);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<string>> GetClientsAsync(
        string sessionId, CancellationToken cancellationToken = default)
    {
        var clients = new List<string>();
        for (var position = 1; position <= MaxClientsPerSession; position++)
        {
            var recorded = await storage.GetAsync<Proto.SessionClient>(
                keyFactory.SessionClientKey(sessionId, position), false, cancellationToken);

            if (recorded == null)
                break;

            clients.Add(recorded.ClientId);
        }

        return clients;
    }

    [LoggerMessage(
        EventId = LogEvents.LogoutNotification.SessionClientRegistry.SessionClientsExhausted,
        Level = LogLevel.Warning,
        Message = "Session {SessionId} already records {Limit} clients, so client {ClientId} is not recorded " +
                  "and will not be notified when the session ends")]
    private partial void LogSessionClientsExhausted(string SessionId, string ClientId, int Limit);
}
