// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Remembers, per polled request, the earliest moment its client may ask again.
/// </summary>
/// <remarks>
/// A record of its own rather than a field on the request it belongs to, and that is the whole point. The
/// polling client asks often and the thing it changes is only this instant, while the user's approval
/// changes the request's status - and a poll that wrote the request back to note the instant overwrote an
/// approval that had landed since it read. The user approved, and the device was told to keep waiting
/// until the code expired.
/// <para>
/// Two polls of the same request can still overwrite each other here, and that is harmless: both write
/// about the same instant, give or take the time between them. What cannot happen any more is a poll
/// writing anything the approval owns.
/// </para>
/// <para>
/// Absence means the client may ask now, so nothing is written when a request is created. The entry
/// expires with the request it belongs to, which is why every write states the remaining lifetime.
/// </para>
/// </remarks>
public interface IPollScheduleStore
{
    /// <summary>
    /// The earliest moment this request's client may ask again, or null when it may ask now.
    /// </summary>
    /// <param name="key">The storage key naming this request's poll schedule.</param>
    /// <returns>The instant, or null when none is recorded.</returns>
    Task<DateTimeOffset?> TryGetNextPollAtAsync(string key);

    /// <summary>
    /// Records the earliest moment this request's client may ask again.
    /// </summary>
    /// <param name="key">The storage key naming this request's poll schedule.</param>
    /// <param name="nextPollAt">The instant before which the client is told to slow down.</param>
    /// <param name="expiresIn">What the request it belongs to has left, so the entry cannot outlive it.</param>
    Task SetNextPollAtAsync(string key, DateTimeOffset nextPollAt, TimeSpan expiresIn);
}
