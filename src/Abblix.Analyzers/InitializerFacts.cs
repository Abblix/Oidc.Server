// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Abblix.Analyzers;

/// <summary>
/// What the initializer of one field or auto-property holds that the codec rule asks about: the codecs it builds and
/// the fields and properties it reads.
/// </summary>
internal sealed class InitializerFacts
{
    /// <summary>The types the codecs built here serve.</summary>
    public List<ITypeSymbol> Served { get; } = [];

    /// <summary>The codecs built here with a mapper.</summary>
    public List<StoredCodec> Codecs { get; } = [];

    /// <summary>The fields and properties read here, whose own codecs a reader of this one takes in too.</summary>
    public List<ISymbol> Read { get; } = [];

    /// <summary>
    /// The facts of <paramref name="initializer"/>, with the codec type asked of through <paramref name="types"/>.
    /// </summary>
    public static InitializerFacts Of(ISymbolInitializerOperation initializer, StoredTypes types)
    {
        var facts = new InitializerFacts();
        foreach (var operation in initializer.Value.DescendantsAndSelf())
        {
            switch (operation)
            {
                case IFieldReferenceOperation field:
                    facts.Read.Add(field.Field.OriginalDefinition);
                    break;

                case IPropertyReferenceOperation property:
                    facts.Read.Add(property.Property.OriginalDefinition);
                    break;
            }

            if (types.ServedBy(operation.Type) is not { } served || served is ITypeParameterSymbol)
                continue;

            facts.Served.Add(served);
            if (operation is IInvocationOperation invocation && StoredCodec.Of(invocation, served) is { } codec)
                facts.Codecs.Add(codec);
        }

        return facts;
    }
}
