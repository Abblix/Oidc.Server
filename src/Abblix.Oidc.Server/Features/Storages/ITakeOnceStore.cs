// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// A store that hands the value at a key to one caller and deletes it, in a step nothing can interleave.
/// </summary>
/// <remarks>
/// An authorization code, a device code and a CIBA request id all stand for an authorization that may be
/// redeemed once. Deciding that from <c>IDistributedCache</c> is not possible: it offers a read, a write
/// and a delete as separate operations, so every protocol assembled from them has a window between two of
/// them where a second caller either wins as well or the value is destroyed with nobody told it won.
/// <para>
/// The server serializes redemptions of one key inside its own process, which settles the question wherever
/// a single process touches that key. Across processes the answer has to come from the store, and every
/// store a deployment would use for this has it: <c>GETDEL</c> in Redis 6.2 and later, a two-line script
/// before that, <c>DELETE ... RETURNING</c> in PostgreSQL, <c>DELETE ... OUTPUT</c> in SQL Server. This is
/// the seam that asks it.
/// </para>
/// <para>
/// Optional by design. A host that registers no implementation keeps the in-process behaviour it has today,
/// which is correct on one instance and probabilistic across several. Registering one is what makes the
/// guarantee hold for a deployment that runs more than one.
/// </para>
/// </remarks>
public interface ITakeOnceStore
{
    /// <summary>
    /// Takes the value stored at <paramref name="key"/> and removes it, indivisibly.
    /// </summary>
    /// <param name="key">The key whose value is being redeemed.</param>
    /// <param name="cancellationToken">Abandons the take when the caller stops waiting.</param>
    /// <returns>
    /// The value that was stored, to exactly one caller among those racing for it, or <c>null</c> when the
    /// key held nothing. An implementation must never answer with the value to two callers, and must never
    /// delete a value without answering with it.
    /// </returns>
    Task<byte[]?> TryTakeAsync(string key, CancellationToken cancellationToken = default);
}
