// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Storages.Proto;
using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Keeps each polled request's next-poll instant in the server's entity storage, under a key of its own.
/// </summary>
/// <param name="storage">Where the instant is kept.</param>
public sealed class PollScheduleStore(IEntityStorage storage) : IPollScheduleStore
{
    /// <inheritdoc />
    public async Task<DateTimeOffset?> TryGetNextPollAtAsync(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        var entry = await storage.GetAsync<PollSchedule>(key, removeOnRetrieval: false);
        return entry?.NextPollAt?.ToDateTimeOffset();
    }

    /// <inheritdoc />
    public Task SetNextPollAtAsync(string key, DateTimeOffset nextPollAt, TimeSpan expiresIn)
    {
        ArgumentNullException.ThrowIfNull(key);

        // Nothing is written once the request it belongs to has no time left: the entry would outlive what
        // it describes, and the caller that hands over a non-positive span is already on its way to
        // telling the client the request expired.
        return expiresIn <= TimeSpan.Zero
            ? Task.CompletedTask
            : storage.SetAsync(
                key,
                new PollSchedule { NextPollAt = nextPollAt.ToTimestamp() },
                new StorageOptions { AbsoluteExpirationRelativeToNow = expiresIn });
    }
}
