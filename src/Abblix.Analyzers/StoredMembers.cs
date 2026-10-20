// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.CodeAnalysis;

namespace Abblix.Analyzers;

/// <summary>
/// The members a mapper owes both directions: the fields of a message and the stored properties of a type it is
/// mapped from.
/// </summary>
/// <param name="types">The symbols the rules are asked of.</param>
/// <param name="setInConstructor">Whether a constructor of its type sets a property with no setter, in its body or
/// through a primary constructor parameter the property's initializer is.</param>
internal sealed class StoredMembers(StoredTypes types, Func<IPropertySymbol, bool> setInConstructor)
{
    /// <summary>
    /// Whether <paramref name="type"/> is declared in this compilation rather than referenced from a built assembly.
    /// </summary>
    public static bool IsInSource(ITypeSymbol type) => type.Locations.Any(location => location.IsInSource);

    /// <summary>
    /// The fields of <paramref name="message"/>: the properties protoc writes a <c>FieldNumber</c> constant for, so
    /// that the presence and clearing members it adds beside a field are not taken for fields.
    /// </summary>
    public static IEnumerable<IPropertySymbol> FieldsOf(ITypeSymbol message)
        => message.GetMembers()
            .OfType<IPropertySymbol>()
            .Where(property => message.GetMembers(property.Name + "FieldNumber")
                .Any(member => member is IFieldSymbol { IsConst: true }));

    /// <summary>
    /// The properties of <paramref name="stored"/> and its base types declared here that hold data: those that can be
    /// written, and auto-properties a constructor sets, but not a computed one or one holding the same value for every
    /// instance, and not one marked as kept out of the message.
    /// </summary>
    public IEnumerable<IPropertySymbol> PropertiesOf(ITypeSymbol stored) => PropertiesUpTo(stored, null);

    /// <summary>
    /// The properties holding data that <paramref name="derived"/> and its base types below
    /// <paramref name="served"/> declare, which a codec of <paramref name="served"/> knows nothing of.
    /// </summary>
    public IEnumerable<IPropertySymbol> PropertiesBelow(ITypeSymbol derived, ITypeSymbol served)
        => PropertiesUpTo(derived, served);

    private IEnumerable<IPropertySymbol> PropertiesUpTo(ITypeSymbol stored, ITypeSymbol? end)
    {
        for (var type = stored;
             type != null && IsInSource(type) && !SymbolEqualityComparer.Default.Equals(type, end);
             type = type.BaseType)
        {
            foreach (var property in HoldingData(type))
                yield return property;
        }
    }

    private IEnumerable<IPropertySymbol> HoldingData(ITypeSymbol type)
    {
        var autoProperties = new HashSet<IPropertySymbol>(
            type.GetMembers().OfType<IFieldSymbol>().Select(field => field.AssociatedSymbol).OfType<IPropertySymbol>(),
            SymbolEqualityComparer.Default);

        return type.GetMembers().OfType<IPropertySymbol>().Where(property =>
            property is { IsStatic: false, IsIndexer: false, IsImplicitlyDeclared: false }
            && (property.SetMethod != null || (autoProperties.Contains(property) && setInConstructor(property)))
            && !types.IsNotStored(property));
    }

    /// <summary>
    /// Whether <paramref name="property"/> of a record is set by a constructor <paramref name="facts"/> call, through
    /// a parameter of its name, which is what a positional record parameter is.
    /// </summary>
    public static bool SetByRecordConstructor(IPropertySymbol property, BodyFacts facts)
        => property.ContainingType.IsRecord
           && facts.Calls.Any(call =>
               call.MethodKind == MethodKind.Constructor
               && SymbolEqualityComparer.Default.Equals(call.ContainingType, property.ContainingType)
               && call.Parameters.Any(parameter => parameter.Name == property.Name));
}
