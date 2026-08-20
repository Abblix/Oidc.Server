// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.ExternalKeys;

/// <inheritdoc />
public sealed class KeyCustodianBuilder(IServiceCollection services) : IKeyCustodianBuilder
{
    /// <inheritdoc />
    public IServiceCollection Services { get; } = services;
}
