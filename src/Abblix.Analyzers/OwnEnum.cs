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
/// An enum whose members the analyzed product decides: declared in an assembly of its family, and not [Flags].
/// </summary>
/// <remarks>
/// The family is the first segment of the assembly name, so <c>Kezio.Domain</c> counts for <c>Kezio.AiLayer</c>.
/// Asked of the assembly rather than of source locations, because an IDE references a neighbour project as source
/// and a build as metadata, and the two would disagree. A foreign enum is dispatched on and refused for the rest far
/// more often than mapped; a [Flags] test asks about one bit rather than picking a member.
/// </remarks>
internal static class OwnEnum
{
    /// <summary>The own enum <paramref name="type"/> names, seen through <see cref="Nullable{T}"/>; null otherwise.</summary>
    public static INamedTypeSymbol? Of(ITypeSymbol? type, Compilation compilation)
    {
        if (type is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T } nullable)
            type = nullable.TypeArguments[0];

        if (type is not INamedTypeSymbol { TypeKind: TypeKind.Enum } enumType
            || !SameFamily(enumType.ContainingAssembly, compilation.Assembly))
        {
            return null;
        }

        return enumType.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == "System.FlagsAttribute")
            ? null
            : enumType;
    }

    /// <summary>The operation beneath any implicit conversion the compiler wrapped it in.</summary>
    public static IOperation Unwrapped(IOperation operation) =>
        operation is IConversionOperation { IsImplicit: true } conversion ? Unwrapped(conversion.Operand) : operation;

    /// <summary>An integral constant's value whatever its width, so a byte member and an int literal agree.</summary>
    /// <remarks>Anything else - a float or a char typed into a switch on an enum while the code does not compile yet - is no member.</remarks>
    public static decimal? Numeric(object? value) =>
        value is not null && IntegralTypes.Contains(value.GetType())
            ? Convert.ToDecimal(value, System.Globalization.CultureInfo.InvariantCulture)
            : null;

    private static readonly HashSet<Type> IntegralTypes =
    [
        typeof(sbyte), typeof(byte), typeof(short), typeof(ushort), typeof(int), typeof(uint), typeof(long), typeof(ulong),
    ];

    private static bool SameFamily(IAssemblySymbol? declaring, IAssemblySymbol analyzed) =>
        declaring is not null
        && string.Equals(FamilyOf(declaring.Name), FamilyOf(analyzed.Name), StringComparison.OrdinalIgnoreCase);

    private static string FamilyOf(string assemblyName)
    {
        var dot = assemblyName.IndexOf('.');
        return dot < 0 ? assemblyName : assemblyName.Substring(0, dot);
    }
}
