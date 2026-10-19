// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// What every part of the key ring is set up with (Parameter Object): the policy the host registered the ring with,
/// the partitions it keeps and the store they share.
/// </summary>
/// <remarks>
/// The store is taken once, here, rather than by each part: a host's store registered for each resolution would
/// otherwise give each part a store of its own, and a deletion would report success over a store no key was ever
/// written to.
/// </remarks>
/// <param name="Policy">What every ring mints, and the key-encryption key sealing it.</param>
/// <param name="PartitionsKept">The partitions to keep.</param>
/// <param name="Store">The store every partition shares.</param>
internal sealed record KeyRingSetup(MintedKeys Policy, IKeyRingPartitions PartitionsKept, IKeyRingStore Store);
