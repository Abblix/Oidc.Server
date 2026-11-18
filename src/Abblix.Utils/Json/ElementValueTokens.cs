// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Frozen;
using System.Text.Json;

namespace Abblix.Utils.Json;

/// <summary>
/// Which reader tokens open a value an element converter can read.
/// </summary>
/// <remarks>
/// Kept outside the generic converters on purpose: a static table in a generic type is built again for every
/// closed type. A JSON <c>null</c> opens a value too, but it is absent here because the array converter keeps it
/// as <c>default</c> without asking the element converter.
/// </remarks>
internal static class ElementValueTokens
{
    private static readonly FrozenSet<JsonTokenType> Tokens = FrozenSet.Create(
        JsonTokenType.String,
        JsonTokenType.Number,
        JsonTokenType.True,
        JsonTokenType.False,
        JsonTokenType.StartObject,
        JsonTokenType.StartArray);

    /// <summary>Whether <paramref name="token"/> opens a value the element converter reads.</summary>
    public static bool Opens(JsonTokenType token) => Tokens.Contains(token);
}
