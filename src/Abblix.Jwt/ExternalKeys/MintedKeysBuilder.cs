// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.ExternalKeys;

/// <inheritdoc />
/// <remarks>
/// The builder owns the policy rather than handing it straight to the ring, because a call after the placement can
/// still change it. The ring reads <see cref="Policy"/> when the container builds it, which is long after every
/// such call has run.
/// </remarks>
internal sealed class MintedKeysBuilder(IServiceCollection services, MintedKeys policy) : IMintedKeysBuilder
{
    /// <inheritdoc />
    public IServiceCollection Services { get; } = services;

    /// <summary>The policy as it stands, including whatever later calls have added to it.</summary>
    public MintedKeys Policy { get; private set; } = policy;

    /// <inheritdoc />
    public IMintedKeysBuilder AdoptExistingKeys(params JsonWebKey[] keys)
    {
        Policy = Policy with { AdoptedKeys = [..Policy.AdoptedKeys, ..keys] };
        return this;
    }
}
