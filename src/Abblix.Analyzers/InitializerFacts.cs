// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.CodeAnalysis;

namespace Abblix.Analyzers;

/// <summary>
/// What the initializer of one field holds that the codec rule asks about: the codecs it builds and the fields it
/// reads.
/// </summary>
internal sealed class FieldFacts
{
    /// <summary>The types the codecs built here serve.</summary>
    public List<ITypeSymbol> Served { get; } = [];

    /// <summary>The codecs built here with a mapper.</summary>
    public List<StoredCodec> Codecs { get; } = [];

    /// <summary>The fields read here, whose own codecs a reader of this field takes in too.</summary>
    public List<IFieldSymbol> Fields { get; } = [];
}
