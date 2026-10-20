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
/// Gathers, over one compilation, the calls to the storage, the codecs of the registry and the bodies their mappers
/// run, and hands them to <see cref="StoredVerdicts"/> once all of it is seen.
/// </summary>
/// <remarks>
/// A codec counts only when it is built in the initializer of a field marked as a codec registry, which is where the
/// serializer takes its codecs from, so a codec built anywhere else serves nothing and is not taken for one that
/// does. A call whose type is a type parameter is skipped only inside a type implementing the storage, which passes
/// its caller's type on to the storage it wraps; anywhere else no codec can be shown for it, and it is reported.
/// </remarks>
/// <param name="types">The symbols the rules are asked of.</param>
internal sealed class StoredMapping(StoredTypes types)
{
    private readonly ConcurrentBag<(ITypeSymbol Type, IMethodSymbol Method, Location Location)> _calls = [];
    private readonly ConcurrentDictionary<ITypeSymbol, bool> _served = new(SymbolEqualityComparer.Default);
    private readonly ConcurrentBag<StoredCodec> _codecs = [];
    private readonly ConcurrentDictionary<IMethodSymbol, BodyFacts> _bodies = new(SymbolEqualityComparer.Default);

    /// <summary>
    /// Notes the codecs a registry field is initialized with.
    /// </summary>
    public void CollectRegistry(OperationAnalysisContext context)
    {
        var initializer = (IFieldInitializerOperation)context.Operation;
        if (!initializer.InitializedFields.Any(types.IsRegistry))
            return;

        foreach (var operation in initializer.Value.DescendantsAndSelf())
        {
            if (types.ServedBy(operation.Type) is not { } served || served is ITypeParameterSymbol)
                continue;

            _served.TryAdd(served, true);
            if (operation is IInvocationOperation invocation && StoredCodec.Of(invocation, served) is { } codec)
                _codecs.Add(codec);
        }
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
        if (stored is ITypeParameterSymbol && context.ContainingSymbol.ContainingType is { } owner && types.IsStorage(owner))
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
        => new StoredVerdicts(types, _served, _bodies).Report(context, _calls, _codecs);
}
