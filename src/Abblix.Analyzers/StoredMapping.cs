// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Abblix.Analyzers;

/// <summary>
/// Gathers, over one compilation, the calls to the storage, the codecs the serializer takes in and the bodies their
/// mappers run, and hands them to <see cref="StoredVerdicts"/> once all of it is seen.
/// </summary>
/// <remarks>
/// A codec counts only when the serializer takes it in: it is built in the initializer of the field marked as the
/// serializer's codecs, or of a field that initializer reads, and on through the fields those read. A codec built
/// anywhere else, a registry nobody wired to the serializer included, serves nothing and is not taken for one that
/// does. A call whose type is a type parameter is skipped only inside a method implementing a member of the storage,
/// which passes its caller's type on to the storage it wraps; anywhere else no codec can be shown for it, and it is
/// reported.
/// </remarks>
/// <param name="types">The symbols the rules are asked of.</param>
internal sealed class StoredMapping(StoredTypes types)
{
    private readonly ConcurrentBag<(ITypeSymbol Type, IMethodSymbol Method, Location Location)> _calls = [];
    private readonly ConcurrentDictionary<IFieldSymbol, FieldFacts> _fields = new(SymbolEqualityComparer.Default);
    private readonly ConcurrentBag<IFieldSymbol> _registries = [];
    private readonly ConcurrentDictionary<IMethodSymbol, BodyFacts> _bodies = new(SymbolEqualityComparer.Default);
    private readonly ConcurrentDictionary<IPropertySymbol, IParameterSymbol[]> _fromParameters =
        new(SymbolEqualityComparer.Default);

    /// <summary>
    /// Notes the codecs a field initializer builds and the fields it reads, and whether it is the serializer's.
    /// </summary>
    public void CollectField(OperationAnalysisContext context)
    {
        var initializer = (IFieldInitializerOperation)context.Operation;
        var facts = new FieldFacts();
        foreach (var operation in initializer.Value.DescendantsAndSelf())
        {
            if (operation is IFieldReferenceOperation reference)
                facts.Fields.Add(reference.Field.OriginalDefinition);

            if (types.ServedBy(operation.Type) is not { } served || served is ITypeParameterSymbol)
                continue;

            facts.Served.Add(served);
            if (operation is IInvocationOperation invocation && StoredCodec.Of(invocation, served) is { } codec)
                facts.Codecs.Add(codec);
        }

        foreach (var field in initializer.InitializedFields)
        {
            _fields[field.OriginalDefinition] = facts;
            if (types.IsRegistry(field))
                _registries.Add(field.OriginalDefinition);
        }
    }

    /// <summary>
    /// Notes a property whose initializer reads a constructor parameter, which a primary constructor sets it through.
    /// </summary>
    public void CollectProperty(OperationAnalysisContext context)
    {
        var initializer = (IPropertyInitializerOperation)context.Operation;
        var parameters = initializer.Value.DescendantsAndSelf()
            .OfType<IParameterReferenceOperation>()
            .Select(reference => reference.Parameter)
            .ToArray();
        if (parameters.Length == 0)
            return;

        foreach (var property in initializer.InitializedProperties)
            _fromParameters.TryAdd(property.OriginalDefinition, parameters);
    }

    /// <summary>
    /// Notes a call to the storage.
    /// </summary>
    public void CollectStorageCall(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;
        if (!method.IsGenericMethod || !types.IsStorageMethod(method))
            return;

        var stored = method.TypeArguments[0];
        if (stored is ITypeParameterSymbol && context.ContainingSymbol is IMethodSymbol caller && types.IsStorageMethod(caller))
            return;

        _calls.Add((stored, method, invocation.Syntax.GetLocation()));
    }

    /// <summary>
    /// Notes what the body of a static method or a constructor touches, for a mapper that calls it.
    /// </summary>
    public void CollectBody(OperationBlockAnalysisContext context)
    {
        if (context.OwningSymbol is IMethodSymbol method
            && (method.IsStatic || method.MethodKind == MethodKind.Constructor))
        {
            _bodies[method.OriginalDefinition] = BodyFacts.Of(context.OperationBlocks);
        }
    }

    /// <summary>
    /// Reports every stored type with no codec and every member a mapper leaves out of a direction.
    /// </summary>
    public void Report(CompilationAnalysisContext context)
    {
        var served = new Dictionary<ITypeSymbol, bool>(SymbolEqualityComparer.Default);
        var codecs = new List<StoredCodec>();
        foreach (var facts in TakenIn())
        {
            foreach (var type in facts.Served)
                served[type] = true;
            codecs.AddRange(facts.Codecs);
        }

        new StoredVerdicts(types, served, _bodies, _fromParameters).Report(context, _calls, codecs);
    }

    /// <summary>
    /// The facts of the fields the serializer takes its codecs from: the marked one and every field it reads, on
    /// through the fields those read.
    /// </summary>
    private IEnumerable<FieldFacts> TakenIn()
    {
        var visited = new HashSet<IFieldSymbol>(SymbolEqualityComparer.Default);
        var pending = new Queue<IFieldSymbol>(_registries);
        while (pending.Count > 0)
        {
            var field = pending.Dequeue();
            if (!visited.Add(field) || !_fields.TryGetValue(field, out var facts))
                continue;

            yield return facts;
            foreach (var read in facts.Fields)
                pending.Enqueue(read);
        }
    }
}
