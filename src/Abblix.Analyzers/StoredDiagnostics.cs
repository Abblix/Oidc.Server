// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace Abblix.Analyzers;

/// <summary>
/// The diagnostics of the stored-type rules, each carrying what it reports as properties a test can read without
/// parsing the message.
/// </summary>
internal static class StoredDiagnostics
{
    /// <summary>
    /// A stored type with no codec, passed to the storage method named.
    /// </summary>
    public static Diagnostic NoCodec(Location location, ITypeSymbol type, IMethodSymbol method)
    {
        var subject = type.ToDisplayString();
        return Diagnostic.Create(
            StoredTypeAnalyzer.CodecRule,
            location,
            ImmutableDictionary<string, string?>.Empty.Add(StoredTypeAnalyzer.SubjectProperty, subject),
            subject,
            method.Name);
    }

    /// <summary>
    /// A member the mapper of a codec leaves out of one direction.
    /// </summary>
    public static Diagnostic Unmapped(Location location, IPropertySymbol member, string direction)
    {
        var subject = $"{member.ContainingType.ToDisplayString()}.{member.Name}";
        return Diagnostic.Create(
            StoredTypeAnalyzer.MappingRule,
            location,
            ImmutableDictionary<string, string?>.Empty
                .Add(StoredTypeAnalyzer.SubjectProperty, subject)
                .Add(StoredTypeAnalyzer.DirectionProperty, direction),
            subject,
            WordsOf(direction));
    }

    /// <summary>
    /// One of several fields marked as the serializer's codecs.
    /// </summary>
    public static Diagnostic ManyRegistries(IFieldSymbol field)
    {
        var subject = $"{field.ContainingType.ToDisplayString()}.{field.Name}";
        return Diagnostic.Create(
            StoredTypeAnalyzer.RegistryRule,
            field.Locations.FirstOrDefault(),
            ImmutableDictionary<string, string?>.Empty.Add(StoredTypeAnalyzer.SubjectProperty, subject),
            subject);
    }

    private static string WordsOf(string direction) => direction switch
    {
        StoredTypeAnalyzer.ToMessage => "to the message",
        StoredTypeAnalyzer.FromMessage => "back from the message",
        _ => throw new ArgumentOutOfRangeException(nameof(direction), direction, "An unknown mapping direction"),
    };
}
