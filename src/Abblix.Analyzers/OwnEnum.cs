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

    /// <summary>A constant's numeric value whatever the underlying type, so a byte member and an int literal agree.</summary>
    public static decimal? Numeric(object? value) => value is null or bool or string ? null : Convert.ToDecimal(value, System.Globalization.CultureInfo.InvariantCulture);

    private static bool SameFamily(IAssemblySymbol? declaring, IAssemblySymbol analyzed) =>
        declaring is not null
        && string.Equals(FamilyOf(declaring.Name), FamilyOf(analyzed.Name), StringComparison.Ordinal);

    private static string FamilyOf(string assemblyName)
    {
        var dot = assemblyName.IndexOf('.');
        return dot < 0 ? assemblyName : assemblyName.Substring(0, dot);
    }
}
