// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Records which clients signed in to an authentication session, so the clients can be told when it ends.
/// </summary>
/// <remarks>
/// Kept on the server rather than in the session. A session travels in the user's cookie, and a browser that
/// authorizes two clients at once sends both requests with the same cookie, so a list inside it can only
/// ever hold the client of whichever response arrived last.
/// <para>
/// Replace the default when the backing store offers an atomic set addition across nodes. The default claims
/// one storage key per client through <see cref="IEntityStorage.TrySetIfAbsentAsync{T}"/>, so between
/// concurrent authorizations it is as exact as the storage's implementation of that call. It also relies on the
/// storage keeping an entry until its expiry: an entry dropped earlier ends the list a logout reads at that
/// point.
/// </para>
/// </remarks>
public interface ISessionClientRegistry
{
    /// <summary>
    /// Records that a client signed in to a session. Recording a client already recorded changes nothing.
    /// </summary>
    /// <param name="sessionId">The session the client signed in to.</param>
    /// <param name="clientId">The client.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task AddClientAsync(string sessionId, string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The clients recorded for a session, each once.
    /// </summary>
    /// <param name="sessionId">The session.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>The recorded client identifiers; empty when none are recorded or the records have expired.</returns>
    Task<IReadOnlyCollection<string>> GetClientsAsync(
        string sessionId, CancellationToken cancellationToken = default);
}
