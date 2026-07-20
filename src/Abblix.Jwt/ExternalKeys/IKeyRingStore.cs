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

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The shared place the server's minted keys live, so every pod serves one key set rather than its own. Entries
/// are encrypted to the custodian's key-encryption key before they get here, so this store holds ciphertext and
/// never a secret.
/// </summary>
/// <remarks>
/// The port is three methods because the design needs no more. Key state is not stored, it is computed: given the
/// entries and their creation times, every pod derives the same announced / active / retired projection by
/// arithmetic, so there is nothing to update and no state machine to synchronise. The single operation that does
/// need synchronising is creating the next key, since two pods would otherwise generate different material, and
/// <see cref="TryAddAsync"/> carries that alone.
/// <para>
/// Because the entry is ciphertext we produced, the store's own protection is not what keeps the key safe: an
/// implementation may be a database, a blob, a config map, or the custodian's own key-value engine, and the
/// threat model does not change with the choice.
/// </para>
/// </remarks>
public interface IKeyRingStore
{
    /// <summary>
    /// Reads every entry. The caller projects the key states from their creation times, so the store neither
    /// filters nor orders.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>All entries currently in the ring.</returns>
    Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Inserts an entry if its <see cref="StoredKey.Id"/> is not taken, and reports whether this caller was the
    /// one that took it.
    /// </summary>
    /// <param name="key">The entry to insert.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>True when this caller inserted the entry; false when another pod had already claimed the id, in
    /// which case the caller re-reads the ring and uses the winner's key.</returns>
    /// <remarks>
    /// This is the whole of the coordination, and it must be atomic in the backing store: a unique index, a
    /// conditional create, a compare-and-set on absence. Two pods minting the same period both attempt the same
    /// id, exactly one gets true, and the loser discards the key it generated. An implementation that cannot
    /// insert atomically cannot back this port.
    /// </remarks>
    Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken);

    /// <summary>
    /// Removes an entry, idempotently: removing an absent id is not an error.
    /// </summary>
    /// <param name="id">The <see cref="StoredKey.Id"/> to remove.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Only ever called for a key already past every token it signed, so removal races are harmless: two pods
    /// removing the same expired entry is the same outcome as one.
    /// </remarks>
    Task RemoveAsync(string id, CancellationToken cancellationToken);
}
