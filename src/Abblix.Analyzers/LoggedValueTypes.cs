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
/// The types <see cref="LoggedValueAnalyzer"/> judges a logging call by, resolved once per compilation.
/// </summary>
internal sealed class LoggedValueTypes
{
    private readonly INamedTypeSymbol _loggerMessage;
    private readonly INamedTypeSymbol _sanitized;
    private readonly INamedTypeSymbol _fingerprint;
    private readonly INamedTypeSymbol _externalInput;
    private readonly INamedTypeSymbol _credential;

    private LoggedValueTypes(
        INamedTypeSymbol loggerMessage,
        INamedTypeSymbol sanitized,
        INamedTypeSymbol fingerprint,
        INamedTypeSymbol externalInput,
        INamedTypeSymbol credential)
    {
        _loggerMessage = loggerMessage;
        _sanitized = sanitized;
        _fingerprint = fingerprint;
        _externalInput = externalInput;
        _credential = credential;
    }

    /// <summary>The types as <paramref name="compilation"/> sees them; null when it misses any of them.</summary>
    public static LoggedValueTypes? Of(Compilation compilation)
    {
        var resolved = (
            compilation.GetTypeByMetadataName(LoggedValueAnalyzer.LoggerMessageAttributeName),
            compilation.GetTypeByMetadataName(LoggedValueAnalyzer.SanitizedName),
            compilation.GetTypeByMetadataName(LoggedValueAnalyzer.FingerprintName),
            compilation.GetTypeByMetadataName(LoggedValueAnalyzer.ExternalInputAttributeName),
            compilation.GetTypeByMetadataName(LoggedValueAnalyzer.CredentialAttributeName));

        return resolved is ({ } loggerMessage, { } sanitized, { } fingerprint, { } externalInput, { } credential)
            ? new LoggedValueTypes(loggerMessage, sanitized, fingerprint, externalInput, credential)
            : null;
    }

    /// <summary>Whether <paramref name="method"/> writes a log record.</summary>
    public bool IsLoggingCall(IMethodSymbol method) => HasAttribute(method.OriginalDefinition, _loggerMessage);

    /// <summary>
    /// Whether a parameter of <paramref name="type"/> can carry text a sender chose: any reference type, and the two
    /// wrappers, but not a count, a flag or an instant.
    /// </summary>
    public bool CanCarryText(ITypeSymbol type) => !type.IsValueType || IsWrapped(type);

    /// <summary>Whether <paramref name="type"/> logs a value as its fingerprint.</summary>
    public bool IsFingerprint(ITypeSymbol type) => Is(Element(type), _fingerprint);

    /// <summary>Whether <paramref name="type"/> logs a value sanitized or as its fingerprint.</summary>
    public bool IsWrapped(ITypeSymbol type) => IsFingerprint(type) || Is(Element(type), _sanitized);

    /// <summary>Whether <paramref name="operation"/> reads a member or a parameter marked as a credential.</summary>
    public bool ReadsCredential(IOperation operation) => operation switch
    {
        IPropertyReferenceOperation read => HasAttribute(read.Property.OriginalDefinition, _credential),
        IFieldReferenceOperation read => HasAttribute(read.Field.OriginalDefinition, _credential),
        IParameterReferenceOperation read => HasAttribute(read.Parameter, _credential),
        _ => false,
    };

    /// <summary>
    /// Whether <paramref name="operation"/> reads a member of a type from outside, or yields such a type itself.
    /// </summary>
    public bool ReadsExternalInput(IOperation operation) => operation switch
    {
        IPropertyReferenceOperation read => FromOutside(read.Property.ContainingType) || FromOutside(read.Type),
        IFieldReferenceOperation read => FromOutside(read.Field.ContainingType) || FromOutside(read.Type),
        IParameterReferenceOperation read => FromOutside(read.Type),
        ILocalReferenceOperation read => FromOutside(read.Type),
        _ => false,
    };

    private bool FromOutside(ITypeSymbol? type)
    {
        for (var current = Element(type); current is not null; current = current.BaseType)
        {
            if (HasAttribute(current.OriginalDefinition, _externalInput))
                return true;
        }

        return false;
    }

    /// <summary>The type <paramref name="type"/> holds, seen through an array and <see cref="Nullable{T}"/>.</summary>
    private static ITypeSymbol? Element(ITypeSymbol? type)
    {
        if (type is IArrayTypeSymbol array)
            type = array.ElementType;

        return type is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T } nullable
            ? nullable.TypeArguments[0]
            : type;
    }

    private static bool Is(ITypeSymbol? type, INamedTypeSymbol expected)
        => SymbolEqualityComparer.Default.Equals(type?.OriginalDefinition, expected);

    private static bool HasAttribute(ISymbol symbol, INamedTypeSymbol attribute)
        => symbol.GetAttributes().Any(data => SymbolEqualityComparer.Default.Equals(data.AttributeClass, attribute));
}
