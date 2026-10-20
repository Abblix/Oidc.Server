// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Abblix.Analyzers;

/// <summary>
/// Decides, once the whole compilation is gathered, which storage calls have no codec and which members a mapper
/// leaves out of a direction.
/// </summary>
/// <remarks>
/// <para>
/// A mapper's direction is its delegate's own body, followed into every static method and constructor it calls or
/// hands on as a delegate whose body is in this compilation, and on from there. Instance methods are not followed,
/// so a mapper reaches only what a mapper is written as.
/// </para>
/// <para>
/// The messages the way out builds are checked field by field, a field being a property protoc writes a
/// <c>FieldNumber</c> constant for. The stored types the way back builds, and the type the codec serves, are checked
/// property by property. A member takes part in a direction when that direction names it, and a property also when
/// that direction calls a constructor setting it: through a positional record parameter of its name, through a
/// parameter the property's initializer or getter reads, or by writing a field its getter reads. A value written by a codec of its base type has properties of its own that codec never
/// writes, so each of them is owed a mark of its own.
/// </para>
/// <para>
/// A finding is shown on the property it is about. A field of a message, which protoc writes, is shown on the codec
/// that writes that message, or, for a message nested in another, on the first codec reaching it in source order, so
/// the place does not change between builds.
/// </para>
/// </remarks>
/// <param name="types">The symbols the rules are asked of.</param>
/// <param name="served">The types the registry has a codec of.</param>
/// <param name="bodies">What each static method and constructor touches.</param>
/// <param name="sources">What each property with no setter reads its value from: the constructor parameters its
/// initializer reads, or the instance fields and primary constructor parameters the getter of a property with no field
/// of its own reads; and for each field, the constructor parameters its initializer reads.</param>
internal sealed class StoredVerdicts(
    StoredTypes types,
    IReadOnlyDictionary<ITypeSymbol, bool> served,
    IReadOnlyDictionary<IMethodSymbol, BodyFacts> bodies,
    IReadOnlyDictionary<ISymbol, BodyFacts> sources)
{
    private readonly StoredMembers _members = new(
        types,
        property => sources.ContainsKey(property) || SetInConstructor(property, bodies));

    /// <summary>
    /// Reports every call with no codec and every member left out of a direction.
    /// </summary>
    public void Report(
        CompilationAnalysisContext context,
        IEnumerable<(ITypeSymbol Type, IMethodSymbol Method, Location Location)> calls,
        IEnumerable<StoredCodec> codecs)
    {
        var reported = new HashSet<(ISymbol, string)>();
        foreach (var (type, method, location) in calls)
        {
            if (served.ContainsKey(type) || types.IsStoredAsJson(type))
                continue;

            if (WrittenAsBase(type, method) is { } baseType)
            {
                foreach (var property in _members.PropertiesBelow(type, baseType))
                    ReportUnmapped(context, reported, property, StoredTypeAnalyzer.ToMessage, location);
                foreach (var field in _members.FieldsBelow(type, baseType))
                    ReportUnmapped(context, reported, field, StoredTypeAnalyzer.ToMessage, location);
                continue;
            }

            context.ReportDiagnostic(StoredDiagnostics.NoCodec(location, type, method));
        }

        var ordered = codecs
            .OrderBy(codec => codec.Location.SourceTree?.FilePath, StringComparer.Ordinal)
            .ThenBy(codec => codec.Location.SourceSpan.Start)
            .ToList();

        foreach (var codec in ordered)
        {
            foreach (var (member, direction) in Unmapped(codec))
            {
                var writer = ordered.FirstOrDefault(other =>
                    SymbolEqualityComparer.Default.Equals(other.Message, member.ContainingType)) ?? codec;
                ReportUnmapped(context, reported, member, direction, writer.Location);
            }
        }
    }

    /// <summary>
    /// The nearest base type with a codec, when <paramref name="method"/> writes a value of <paramref name="type"/>,
    /// which the serializer then writes by that codec; a value read back is asked for by exactly the type named.
    /// </summary>
    private ITypeSymbol? WrittenAsBase(ITypeSymbol type, IMethodSymbol method)
    {
        if (!method.Parameters.Any(parameter => SymbolEqualityComparer.Default.Equals(parameter.Type, type)))
            return null;

        for (var baseType = type.BaseType; baseType != null; baseType = baseType.BaseType)
        {
            if (served.ContainsKey(baseType))
                return baseType;
        }

        return null;
    }

    private void ReportUnmapped(
        CompilationAnalysisContext context,
        HashSet<(ISymbol, string)> reported,
        ISymbol member,
        string direction,
        Location fallback)
    {
        if (!reported.Add((member, direction)))
            return;

        var location = !types.IsMessage(member.ContainingType)
                       && member.Locations.FirstOrDefault(candidate => candidate.IsInSource) is { } declared
            ? declared
            : fallback;
        context.ReportDiagnostic(StoredDiagnostics.Unmapped(location, member, direction));
    }

    /// <summary>
    /// Each member of a message the way out builds, or of a type the way back builds, that one of the two directions
    /// does not name, with the direction it is missing from.
    /// </summary>
    private IEnumerable<(ISymbol Member, string Direction)> Unmapped(StoredCodec codec)
    {
        var outward = Closure(codec.Out);
        var back = Closure(codec.Back);

        var messages = outward.Created.Where(type => types.IsMessage(type) && StoredMembers.IsInSource(type));
        var fields = messages.SelectMany(StoredMembers.MessageFieldsOf)
            .Select(field => ((ISymbol)field, outward.Properties.Contains(field), back.Properties.Contains(field)));

        var rebuilt = back.Created
            .Where(type => !types.IsMessage(type) && StoredMembers.IsInSource(type))
            .Append(codec.Value)
            .Distinct(SymbolEqualityComparer.Default)
            .OfType<ITypeSymbol>();
        var properties = rebuilt.SelectMany(_members.PropertiesOf)
            .Select(property => (
                (ISymbol)property,
                outward.Properties.Contains(property),
                back.Properties.Contains(property) || SetByConstructor(property, back)));

        // A field a stored property's getter reads is mapped through that property; any other field is mapped itself
        var data = rebuilt.SelectMany(_members.FieldsOf)
            .Where(field => !ReadByStoredProperty(field))
            .Select(field => (
                (ISymbol)field,
                outward.Fields.Contains(field),
                back.Fields.Contains(field) || SetFieldByConstructor(field, back)));

        foreach (var (member, isOut, isBack) in fields.Concat(properties).Concat(data))
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
            if (!visited.Add(method) || !bodies.TryGetValue(method, out var body))
                continue;

            all.Add(body);
            foreach (var call in body.Calls)
                pending.Enqueue(call);
        }

        return all;
    }

    /// <summary>
    /// Whether a constructor <paramref name="facts"/> call sets <paramref name="property"/>: through a positional
    /// record parameter of its name, through a parameter its initializer or getter reads, or by writing a field its
    /// getter reads.
    /// </summary>
    private bool SetByConstructor(IPropertySymbol property, BodyFacts facts)
    {
        if (StoredMembers.SetByRecordConstructor(property, facts))
            return true;

        if (!sources.TryGetValue(property, out var source))
            return false;

        var constructors = facts.Calls.Where(call => call.MethodKind == MethodKind.Constructor).ToList();
        return constructors.Any(constructor =>
            OwnsAny(constructor, source.Parameters)
            || (bodies.TryGetValue(constructor, out var body) && body.Fields.Overlaps(source.Fields))
            || source.Fields.Any(field =>
                sources.TryGetValue(field, out var initializer) && OwnsAny(constructor, initializer.Parameters)));
    }

    /// <summary>
    /// Whether the getter of a property of the field's type that is not kept out of the message reads
    /// <paramref name="field"/>.
    /// </summary>
    private bool ReadByStoredProperty(IFieldSymbol field)
        => sources.Any(source =>
            source.Key is IPropertySymbol property
            && SymbolEqualityComparer.Default.Equals(property.ContainingType, field.ContainingType)
            && !types.IsNotStored(property)
            && source.Value.Fields.Contains(field));

    /// <summary>
    /// Whether a constructor <paramref name="facts"/> call sets <paramref name="field"/>, in its body or through a
    /// parameter the field's initializer reads.
    /// </summary>
    private bool SetFieldByConstructor(IFieldSymbol field, BodyFacts facts)
        => facts.Calls.Where(call => call.MethodKind == MethodKind.Constructor).Any(constructor =>
            (bodies.TryGetValue(constructor, out var body) && body.Fields.Contains(field))
            || (sources.TryGetValue(field, out var initializer) && OwnsAny(constructor, initializer.Parameters)));

    private static bool OwnsAny(IMethodSymbol constructor, IEnumerable<IParameterSymbol> parameters)
        => parameters.Any(parameter =>
            SymbolEqualityComparer.Default.Equals(parameter.ContainingSymbol.OriginalDefinition, constructor));

    private static bool SetInConstructor(IPropertySymbol property, IReadOnlyDictionary<IMethodSymbol, BodyFacts> bodies)
        => property.ContainingType.InstanceConstructors.Any(constructor =>
            bodies.TryGetValue(constructor.OriginalDefinition, out var body) && body.Properties.Contains(property));
}
