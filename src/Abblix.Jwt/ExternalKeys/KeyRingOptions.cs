// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Configuration of the key ring.
/// </summary>
public sealed class KeyRingOptions
{
    /// <summary>
    /// How long a newly minted key is published before the ring starts producing with it.
    /// </summary>
    /// <remarks>
    /// A consumer caches the published key set, so a key that starts signing the moment it appears will sign
    /// tokens that consumers with a warm cache cannot yet verify. Publishing first and producing later closes
    /// that window: by the time a key leads its algorithm, every consumer refreshing on the usual schedule has
    /// already seen it.
    ///
    /// The value is therefore a property of how long consumers cache, not of how often keys rotate. An hour
    /// covers the caching most providers and clients default to.
    /// </remarks>
    public TimeSpan KeyRolloverPropagation { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The partition a ring serving one issuer keeps, whose entries are stored under their own ids.
    /// </summary>
    public const string DefaultPartition = "";

    /// <summary>
    /// The partitions the key ring keeps, each a ring of its own that mints, rotates and serves keys apart from the
    /// others, so no two partitions share a key. A server with one issuer keeps the default one; one serving
    /// several tenants keeps one for each.
    /// </summary>
    /// <remarks>
    /// All partitions share the store: an entry of a partition other than the default is stored under its id with
    /// the partition name and a dot in front, which is why a name holds only letters, digits, '-' and '_', and why
    /// the default partition keeps only entries whose id has no dot.
    /// </remarks>
    public IReadOnlyCollection<string> Partitions { get; set; } = [DefaultPartition];

    /// <summary>
    /// Whether <paramref name="partition"/> can name a partition: its name goes in front of its entries' ids in
    /// the store, so it holds only letters, digits, '-' and '_', which every store accepts and none is a dot.
    /// </summary>
    /// <param name="partition">The name to judge.</param>
    public static bool IsPartitionName(string partition)
        => partition.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
