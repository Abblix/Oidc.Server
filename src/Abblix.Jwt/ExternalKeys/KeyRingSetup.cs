// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// What every part of the key ring is set up with (Parameter Object): the policy the host registered the ring with
/// and the partitions it keeps.
/// </summary>
/// <param name="Policy">What every ring mints, and the key-encryption key sealing it.</param>
/// <param name="PartitionsKept">The partitions to keep.</param>
internal sealed record KeyRingSetup(MintedKeys Policy, IKeyRingPartitions PartitionsKept);
