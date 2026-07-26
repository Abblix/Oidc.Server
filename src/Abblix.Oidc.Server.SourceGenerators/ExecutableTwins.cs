// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Microsoft.CodeAnalysis;

namespace Abblix.Oidc.Server.SourceGenerators;

/// <summary>
/// Resolves the executable attribute a declarative core marker is mirrored by.
/// </summary>
/// <remarks>
/// Shared by both adapter generators on purpose. They used to answer this question differently - one by
/// convention, matching the marker's simple name inside a namespace resolved from an anchor type, and the
/// other from a constant naming each executable attribute in full - and two answers to one question is how
/// the adapters drift: a marker that is renamed or moves namespace then has to be taught to each generator
/// separately, and the one nobody remembered keeps emitting the old reference until a build somewhere fails.
///
/// The rule is the convention the whole mirroring rests on: the executable twin carries the marker's name,
/// in the namespace this library keeps its validation attributes in. The namespace is not written out here -
/// the caller derives it from an anchor type, so the lookup follows the attributes if they move.
///
/// The lookup cannot fail silently: a marker with no twin resolves to null, and both generators turn that
/// into a loud diagnostic rather than dropping the attribute from the generated model. That is the property
/// the per-attribute constants were defending, and it survives the move to a convention because the miss is
/// still reported per attribute rather than per namespace.
/// </remarks>
internal static class ExecutableTwins
{
    /// <summary>
    /// The executable attribute mirroring <paramref name="markerName"/>, or <c>null</c> when this library
    /// declares none by that name.
    /// </summary>
    /// <param name="compilation">The compilation to resolve against.</param>
    /// <param name="validationNamespace">
    /// The namespace this library keeps its executable validation attributes in, resolved from an anchor
    /// type by the caller rather than written out, so the lookup follows the attributes if they move.
    /// </param>
    /// <param name="markerName">The metadata name of the declarative marker, without its namespace.</param>
    public static INamedTypeSymbol? Resolve(
        Compilation compilation, string? validationNamespace, string markerName)
        => validationNamespace is null
            ? null
            : compilation.GetTypeByMetadataName($"{validationNamespace}.{markerName}");
}
