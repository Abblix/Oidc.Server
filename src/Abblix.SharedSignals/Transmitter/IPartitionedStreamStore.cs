// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// A stream store that keeps a separate set of streams for each partition, so listing one partition's streams reads
/// that partition's alone.
/// </summary>
/// <remarks>
/// A transmitter serving several parties, as one tenant each, asks for the store of the party it serves. One sharing a
/// store without partitions between its parties reads every party's streams on each listing.
/// </remarks>
public interface IPartitionedStreamStore : IStreamStore
{
    /// <summary>
    /// The store of <paramref name="partition"/>'s streams, apart from every other partition's and from the streams
    /// this store holds itself.
    /// </summary>
    /// <param name="partition">The partition, an opaque name the caller keeps stable for as long as its streams
    /// live.</param>
    IStreamStore Partition(string partition);
}
