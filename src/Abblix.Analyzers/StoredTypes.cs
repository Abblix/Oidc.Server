// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.CodeAnalysis;

namespace Abblix.Analyzers;

/// <summary>
/// The symbols the stored-type rules are asked of, resolved once per compilation.
/// </summary>
/// <param name="storage">The entity storage interface.</param>
/// <param name="codec">The generic codec type.</param>
/// <param name="message">The interface every Protocol Buffers message implements, when the compilation sees it.</param>
/// <param name="storedAsJson">The mark of a type stored as JSON on purpose, when declared.</param>
/// <param name="notStored">The mark of a property kept out of the message on purpose, when declared.</param>
internal sealed class StoredTypes(
    INamedTypeSymbol storage,
    INamedTypeSymbol codec,
    INamedTypeSymbol? message,
    INamedTypeSymbol? storedAsJson,
    INamedTypeSymbol? notStored)
{
    /// <summary>
    /// The symbols of <paramref name="compilation"/>, or null when it does not declare the codec itself.
    /// </summary>
    /// <remarks>
    /// The codecs are built where the codec is declared, and a compilation that only references that assembly sees
    /// none of them, so every storage call of a test or a neighbouring package would read as one without a codec.
    /// </remarks>
    public static StoredTypes? Of(Compilation compilation)
        => compilation.GetTypeByMetadataName(StoredTypeAnalyzer.StorageName) is { } storage
           && compilation.GetTypeByMetadataName(StoredTypeAnalyzer.CodecName) is { } codec
           && SymbolEqualityComparer.Default.Equals(codec.ContainingAssembly, compilation.Assembly)
            ? new StoredTypes(
                storage,
                codec,
                compilation.GetTypeByMetadataName(StoredTypeAnalyzer.MessageName),
                compilation.GetTypeByMetadataName(StoredTypeAnalyzer.StoredAsJsonName),
                compilation.GetTypeByMetadataName(StoredTypeAnalyzer.NotStoredName))
            : null;

    /// <summary>
    /// Whether <paramref name="method"/> is a member of the storage, called on the interface or on an
    /// implementation, rather than some other method of a type that happens to implement it.
    /// </summary>
    public bool IsStorageMethod(IMethodSymbol method)
    {
        var definition = method.OriginalDefinition;
        return storage.GetMembers().OfType<IMethodSymbol>().Any(member =>
            SymbolEqualityComparer.Default.Equals(member, definition)
            || SymbolEqualityComparer.Default.Equals(
                definition.ContainingType.FindImplementationForInterfaceMember(member), definition));
    }

    /// <summary>
    /// The type a codec serves, when <paramref name="type"/> is a codec.
    /// </summary>
    public ITypeSymbol? ServedBy(ITypeSymbol? type)
        => type is INamedTypeSymbol { IsGenericType: true } named
           && SymbolEqualityComparer.Default.Equals(named.OriginalDefinition, codec)
            ? named.TypeArguments[0]
            : null;

    /// <summary>
    /// Whether <paramref name="type"/> is a Protocol Buffers message.
    /// </summary>
    public bool IsMessage(ITypeSymbol type)
        => message != null && type.AllInterfaces.Contains(message, SymbolEqualityComparer.Default);

    /// <summary>
    /// Whether <paramref name="type"/> is stored as JSON on purpose.
    /// </summary>
    public bool IsStoredAsJson(ITypeSymbol type) => HasMark(type, storedAsJson);

    /// <summary>
    /// Whether <paramref name="property"/> is kept out of the message on purpose.
    /// </summary>
    public bool IsNotStored(IPropertySymbol property) => HasMark(property, notStored);

    private static bool HasMark(ISymbol symbol, INamedTypeSymbol? mark)
        => mark != null && symbol.GetAttributes().Any(attribute =>
            SymbolEqualityComparer.Default.Equals(attribute.AttributeClass, mark));
}
