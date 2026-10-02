// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The partitions the settings declare, which the ring keeps when the host registers no
/// <see cref="IKeyRingPartitions"/> of its own.
/// </summary>
internal sealed class OptionsKeyRingPartitions(IOptions<KeyRingOptions> options) : IKeyRingPartitions
{
    /// <inheritdoc />
    public IReadOnlyCollection<string> Kept => options.Value.Partitions;
}
