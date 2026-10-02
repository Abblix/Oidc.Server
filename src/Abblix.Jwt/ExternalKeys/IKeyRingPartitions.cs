// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The partitions the key ring keeps current, each refreshed on the ring's schedule.
/// </summary>
/// <remarks>
/// With none registered the ring keeps <see cref="KeyRingOptions.Partitions"/>, which are fixed when the host starts.
/// A server whose issuers come and go while it runs registers its own, answering with the partitions of the issuers
/// it serves now, and opens each new one through <see cref="IKeyRings.OpenAsync"/> before serving it.
/// </remarks>
public interface IKeyRingPartitions
{
    /// <summary>
    /// The partitions kept now.
    /// </summary>
    IReadOnlyCollection<string> Kept { get; }
}
