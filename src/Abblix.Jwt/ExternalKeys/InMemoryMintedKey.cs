// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// A key the in-memory ring minted, with the moment it was made, which is what decides producing order and
/// retirement.
/// </summary>
/// <param name="Key">The key.</param>
/// <param name="CreatedAt">When it was minted.</param>
internal sealed record InMemoryMintedKey(JsonWebKey Key, DateTimeOffset CreatedAt);
