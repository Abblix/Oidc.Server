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
/// Which codecs count is worked out by <see cref="CodecRegistry"/>. A call whose type is a type parameter is skipped
/// only inside a method implementing a member of the storage, which passes its caller's type on to the storage it
/// wraps; anywhere else no codec can be shown for it, and it is reported.
/// </remarks>
/// <param name="types">The symbols the rules are asked of.</param>
internal sealed class StoredMapping(StoredTypes types)
{
    private readonly ConcurrentBag<(ITypeSymbol Type, IMethodSymbol Method, Location Location)> _calls = [];
    private readonly CodecRegistry _registry = new();
    private readonly ConcurrentDictionary<IMethodSymbol, BodyFacts> _bodies = new(SymbolEqualityComparer.Default);
    private readonly ConcurrentDictionary<IPropertySymbol, IParameterSymbol[]> _fromParameters =
        new(SymbolEqualityComparer.Default);

    /// <summary>
    /// Notes the codecs a field initializer builds and the members it reads, and whether it is the serializer's.
    /// </summary>
    public void CollectField(OperationAnalysisContext context)
    {
        var initializer = (IFieldInitializerOperation)context.Operation;
        var facts = InitializerFacts.Of(initializer, types);
        foreach (var field in initializer.InitializedFields)
            _registry.Add(field, facts, types.IsRegistry(field));
    }

    /// <summary>
    /// Notes the codecs an auto-property initializer builds and the members it reads, and whether it hands on a
    /// constructor parameter as it is, which a primary constructor sets the property through.
    /// </summary>
    public void CollectProperty(OperationAnalysisContext context)
    {
        var initializer = (IPropertyInitializerOperation)context.Operation;
        var facts = InitializerFacts.Of(initializer, types);
        foreach (var property in initializer.InitializedProperties)
            _registry.Add(property, facts, marked: false);

        // A value computed from a parameter is computed again by the constructor, so only the parameter itself is data
        var value = initializer.Value;
        while (value is IConversionOperation conversion)
            value = conversion.Operand;

        if (value is not IParameterReferenceOperation reference)
            return;

        foreach (var property in initializer.InitializedProperties)
            _fromParameters.TryAdd(property.OriginalDefinition, [reference.Parameter]);
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
        _registry.ReportMarks(context);
        var (served, codecs) = _registry.TakenIn();
        new StoredVerdicts(types, served, _bodies, _fromParameters).Report(context, _calls, codecs);
    }
}
