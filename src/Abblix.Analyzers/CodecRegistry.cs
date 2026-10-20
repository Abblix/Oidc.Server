// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Abblix.Analyzers;

/// <summary>
/// The codecs the serializer takes in, worked out from the initializers of the compilation's fields and
/// auto-properties once all of them are seen.
/// </summary>
/// <remarks>
/// A codec counts only when it is built in the initializer of the one field marked as the serializer's codecs, or of a
/// field or auto-property that initializer reads, and on through the members those read. A codec built anywhere else,
/// a registry nobody wired to the serializer included, serves nothing. A member read counts whole, even where the
/// initializer filters some of its codecs out.
/// </remarks>
internal sealed class CodecRegistry
{
    private readonly ConcurrentDictionary<ISymbol, InitializerFacts> _initializers = new(SymbolEqualityComparer.Default);
    private readonly ConcurrentBag<IFieldSymbol> _marked = [];

    /// <summary>
    /// Notes the facts of the initializer of <paramref name="member"/>, and whether it carries the mark.
    /// </summary>
    public void Add(ISymbol member, InitializerFacts facts, bool marked)
    {
        _initializers[member.OriginalDefinition] = facts;
        if (marked && member is IFieldSymbol field)
            _marked.Add(field.OriginalDefinition);
    }

    /// <summary>
    /// Reports each marked field when more than one is, since only one of them can be the serializer's.
    /// </summary>
    public void ReportMarks(CompilationAnalysisContext context)
    {
        var marked = _marked.Distinct(SymbolEqualityComparer.Default).OfType<IFieldSymbol>().ToList();
        if (marked.Count <= 1)
            return;

        foreach (var field in marked)
            context.ReportDiagnostic(StoredDiagnostics.ManyRegistries(field));
    }

    /// <summary>
    /// The types the serializer has a codec of, and the codecs among them built with a mapper.
    /// </summary>
    public (Dictionary<ITypeSymbol, bool> Served, List<StoredCodec> Codecs) TakenIn()
    {
        var served = new Dictionary<ITypeSymbol, bool>(SymbolEqualityComparer.Default);
        var codecs = new List<StoredCodec>();

        var visited = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
        var pending = new Queue<ISymbol>(_marked);
        while (pending.Count > 0)
        {
            var member = pending.Dequeue();
            if (!visited.Add(member) || !_initializers.TryGetValue(member, out var facts))
                continue;

            foreach (var type in facts.Served)
                served[type] = true;
            codecs.AddRange(facts.Codecs);

            foreach (var read in facts.Read)
                pending.Enqueue(read);
        }

        return (served, codecs);
    }
}
