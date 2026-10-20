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
/// Gathers, over one compilation, the calls to the storage, the codecs built and the bodies their mappers run, and
/// reports what the two stored-type rules refuse once all of it is seen.
/// </summary>
/// <remarks>
/// <para>
/// A codec built from two delegates has a mapper: the delegate returning the stored type reads it back, the other
/// writes it out. Each direction is the delegate's own body, followed into every static method and constructor it
/// calls whose body is in this compilation, and on from there. Instance methods are not followed, so a mapper reaches
/// only what a mapper is written as, and the code a stored type happens to call elsewhere does not count as mapping.
/// </para>
/// <para>
/// The messages a direction builds are checked field by field, a field being a property protoc writes a
/// <c>FieldNumber</c> constant for. The stored types a direction builds back, and the type the codec serves, are
/// checked property by property, a property being stored when it can be written or is an auto-property set in a
/// constructor; a computed one is not. A member takes part in a direction when that direction names it, and a
/// property of a record also when that direction calls the record's constructor with a parameter of its name, which
/// is what a positional record parameter is.
/// </para>
/// </remarks>
/// <param name="types">The symbols the rules are asked of.</param>
internal sealed class StoredMapping(StoredTypes types)
{
    private readonly ConcurrentBag<(ITypeSymbol Type, IMethodSymbol Method, Location Location)> _calls = [];
    private readonly ConcurrentDictionary<ITypeSymbol, bool> _served = new(SymbolEqualityComparer.Default);
    private readonly ConcurrentBag<(ITypeSymbol Value, Location Location, BodyFacts Out, BodyFacts Back)> _codecs = [];
    private readonly ConcurrentDictionary<IMethodSymbol, BodyFacts> _bodies = new(SymbolEqualityComparer.Default);
    private readonly StoredMembers _members = new(types);

    /// <summary>
    /// Notes a call to the storage, or a codec being built.
    /// </summary>
    public void CollectInvocation(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;

        if (types.ServedBy(invocation.Type) is { } served)
        {
            // A codec built for a type parameter is a factory building one for its caller, which is checked there
            if (served is ITypeParameterSymbol)
                return;

            _served.TryAdd(served, true);
            CollectMapper(invocation, served);
            return;
        }

        // A type parameter passes the decision to the caller that names the type
        if (method is { IsGenericMethod: true } && types.IsStorageMethod(method)
            && method.TypeArguments[0] is not ITypeParameterSymbol)
        {
            _calls.Add((method.TypeArguments[0], method, invocation.Syntax.GetLocation()));
        }
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
        foreach (var (type, method, location) in _calls)
        {
            if (!HasCodec(type, method))
            {
                context.ReportDiagnostic(StoredDiagnostics.NoCodec(location, type, method));
            }
        }

        var reported = new HashSet<(ISymbol, string)>();
        foreach (var codec in _codecs)
            ReportMapping(context, codec, reported);
    }

    private void CollectMapper(IInvocationOperation invocation, ITypeSymbol served)
    {
        BodyFacts? outward = null, back = null;
        foreach (var argument in invocation.Arguments)
        {
            if (argument is not { Value: IDelegateCreationOperation creation, Parameter.Type: INamedTypeSymbol delegateType }
                || delegateType.DelegateInvokeMethod is not { } invoke)
            {
                continue;
            }

            var facts = creation.Target switch
            {
                IAnonymousFunctionOperation function => BodyFacts.Of([function.Body]),
                IMethodReferenceOperation reference => CallOf(reference.Method),
                _ => new BodyFacts(),
            };

            if (SymbolEqualityComparer.Default.Equals(invoke.ReturnType, served))
                back = facts;
            else
                outward = facts;
        }

        if (outward != null && back != null)
            _codecs.Add((served, invocation.Syntax.GetLocation(), outward, back));
    }

    private static BodyFacts CallOf(IMethodSymbol method)
    {
        var facts = new BodyFacts();
        facts.Calls.Add(method.OriginalDefinition);
        return facts;
    }

    private bool HasCodec(ITypeSymbol type, IMethodSymbol method)
    {
        if (_served.ContainsKey(type) || types.IsStoredAsJson(type))
            return true;

        // A value being written is matched by its own type first and then by its base types, as the serializer does
        // at run time; a value read back is asked for by exactly the type named
        var writes = method.Parameters.Any(parameter =>
            SymbolEqualityComparer.Default.Equals(parameter.Type, type));
        for (var baseType = type.BaseType; writes && baseType != null; baseType = baseType.BaseType)
        {
            if (_served.ContainsKey(baseType))
                return true;
        }

        return false;
    }

    private void ReportMapping(
        CompilationAnalysisContext context,
        (ITypeSymbol Value, Location Location, BodyFacts Out, BodyFacts Back) codec,
        HashSet<(ISymbol, string)> reported)
    {
        var outward = Closure(codec.Out);
        var back = Closure(codec.Back);

        foreach (var (member, direction) in Unmapped(codec.Value, outward, back))
        {
            if (!reported.Add((member, direction)))
                continue;

            context.ReportDiagnostic(StoredDiagnostics.Unmapped(codec.Location, member, direction));
        }
    }

    /// <summary>
    /// Each member of a message the outward direction builds, or of a type the direction back builds, that one of the
    /// two directions does not name, with the direction it is missing from.
    /// </summary>
    private IEnumerable<(IPropertySymbol Member, string Direction)> Unmapped(
        ITypeSymbol value, BodyFacts outward, BodyFacts back)
    {
        var messages = outward.Created.Where(type => types.IsMessage(type) && StoredMembers.IsInSource(type));
        var fields = messages.SelectMany(StoredMembers.FieldsOf)
            .Select(field => (field, outward.Properties.Contains(field), back.Properties.Contains(field)));

        var rebuilt = back.Created
            .Where(type => !types.IsMessage(type) && StoredMembers.IsInSource(type))
            .Append(value)
            .Distinct(SymbolEqualityComparer.Default)
            .OfType<ITypeSymbol>();
        var properties = rebuilt.SelectMany(_members.PropertiesOf)
            .Select(property => (
                property,
                outward.Properties.Contains(property),
                back.Properties.Contains(property) || StoredMembers.SetByRecordConstructor(property, back)));

        foreach (var (member, isOut, isBack) in fields.Concat(properties))
        {
            if (!isOut)
                yield return (member, StoredTypeAnalyzer.ToMessage);
            if (!isBack)
                yield return (member, StoredTypeAnalyzer.FromMessage);
        }
    }

    private BodyFacts Closure(BodyFacts start)
    {
        var all = new BodyFacts();
        all.Add(start);

        var visited = new HashSet<IMethodSymbol>(SymbolEqualityComparer.Default);
        var pending = new Queue<IMethodSymbol>(start.Calls);
        while (pending.Count > 0)
        {
            var method = pending.Dequeue();
            if (!visited.Add(method) || !_bodies.TryGetValue(method, out var body))
                continue;

            all.Add(body);
            foreach (var call in body.Calls)
                pending.Enqueue(call);
        }

        return all;
    }
}
