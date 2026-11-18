// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Records that the host registered a stream store keeping partitions, so a transmitter serving several parties can
/// tell when the store it is handed hides those partitions, as a wrapper the host put around it does.
/// </summary>
/// <remarks>
/// Registered by the call that registers such a store, such as the Redis stream store's. A store handed out in its
/// place that keeps no partitions would read every party's streams from where none of them were stored.
/// </remarks>
/// <param name="storeType">The type of the stream store registered.</param>
public sealed class PartitionedStreamStoreRegistration(Type storeType)
{
    /// <summary>
    /// The type of the stream store registered.
    /// </summary>
    public Type StoreType { get; } = storeType;
}
