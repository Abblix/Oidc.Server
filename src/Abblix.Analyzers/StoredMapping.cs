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
    private readonly ConcurrentDictionary<ISymbol, BodyFacts> _sources = new(SymbolEqualityComparer.Default);

    /// <summary>
    /// Notes the codecs a field initializer builds and the members it reads, and whether it is the serializer's.
    /// </summary>
    public void CollectField(OperationAnalysisContext context)
    {
        var initializer = (IFieldInitializerOperation)context.Operation;
        var facts = InitializerFacts.Of(initializer, types);
        foreach (var field in initializer.InitializedFields)
            _registry.Add(field, facts, types.IsRegistry(field));

        // A field a primary constructor sets through its initializer passes the parameter on to a property reading it
        var read = BodyFacts.Of([initializer.Value]);
        if (!read.Parameters.Any(IsConstructorParameter))
            return;

        foreach (var field in initializer.InitializedFields)
            _sources.TryAdd(field.OriginalDefinition, read);
    }

    /// <summary>
    /// Notes the codecs an auto-property initializer builds and the members it reads, and the constructor parameters
    /// it reads, which a primary constructor sets the property through.
    /// </summary>
    public void CollectProperty(OperationAnalysisContext context)
    {
        var initializer = (IPropertyInitializerOperation)context.Operation;
        var facts = InitializerFacts.Of(initializer, types);
        foreach (var property in initializer.InitializedProperties)
            _registry.Add(property, facts, marked: false);

        // A value computed from a parameter counts too: wrongly reported, it asks for a reasoned mark, while a value
        // let through unchecked would be lost with nothing said
        var read = BodyFacts.Of([initializer.Value]);
        if (!read.Parameters.Any(IsConstructorParameter))
            return;

        foreach (var property in initializer.InitializedProperties)
            _sources.TryAdd(property.OriginalDefinition, read);
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
        if (context.OwningSymbol is not IMethodSymbol method)
            return;

        if (method.IsStatic || method.MethodKind == MethodKind.Constructor)
        {
            _bodies[method.OriginalDefinition] = BodyFacts.Of(context.OperationBlocks);
            return;
        }

        // A property with no field of its own holds data when its getter reads an instance field or a primary
        // constructor parameter
        if (method is { MethodKind: MethodKind.PropertyGet, AssociatedSymbol: IPropertySymbol property })
        {
            var read = BodyFacts.Of(context.OperationBlocks);
            if (read.Fields.Count > 0 || read.Parameters.Any(IsConstructorParameter))
                _sources.TryAdd(property.OriginalDefinition, read);
        }
    }

    private static bool IsConstructorParameter(IParameterSymbol parameter)
        => parameter.ContainingSymbol is IMethodSymbol { MethodKind: MethodKind.Constructor };

    /// <summary>
    /// Reports every stored type with no codec and every member a mapper leaves out of a direction.
    /// </summary>
    public void Report(CompilationAnalysisContext context)
    {
        _registry.ReportMarks(context);
        var (served, codecs) = _registry.TakenIn();
        new StoredVerdicts(types, served, _bodies, _sources).Report(context, _calls, codecs);
    }
}
