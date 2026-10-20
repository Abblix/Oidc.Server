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
/// A codec of the registry built with a mapper: the type it serves, the message it writes that type as, and what each
/// of its two delegates touches.
/// </summary>
/// <param name="value">The stored type the codec serves.</param>
/// <param name="message">The message the way out returns.</param>
/// <param name="location">Where the codec is built.</param>
/// <param name="outward">What the delegate writing the value out as its message touches.</param>
/// <param name="back">What the delegate reading the value back touches.</param>
internal sealed class StoredCodec(
    ITypeSymbol value,
    ITypeSymbol message,
    Location location,
    BodyFacts outward,
    BodyFacts back)
{
    /// <summary>The stored type the codec serves.</summary>
    public ITypeSymbol Value => value;

    /// <summary>The message the way out returns.</summary>
    public ITypeSymbol Message => message;

    /// <summary>Where the codec is built.</summary>
    public Location Location => location;

    /// <summary>What the delegate writing the value out as its message touches.</summary>
    public BodyFacts Out => outward;

    /// <summary>What the delegate reading the value back touches.</summary>
    public BodyFacts Back => back;

    /// <summary>
    /// The codec <paramref name="invocation"/> builds for <paramref name="served"/>, or null when it is not built from
    /// two delegates, as a codec of a message stored as itself or of text is not.
    /// </summary>
    /// <remarks>
    /// The delegate returning the stored type reads it back; the other writes it out, and what it returns is the
    /// message.
    /// </remarks>
    public static StoredCodec? Of(IInvocationOperation invocation, ITypeSymbol served)
    {
        (BodyFacts Facts, ITypeSymbol Returns)? outward = null;
        BodyFacts? back = null;
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
                IMethodReferenceOperation reference => BodyFacts.Calling(reference.Method),
                _ => new BodyFacts(),
            };

            if (SymbolEqualityComparer.Default.Equals(invoke.ReturnType, served))
                back = facts;
            else
                outward = (facts, invoke.ReturnType);
        }

        return outward is { } way && back != null
            ? new StoredCodec(served, way.Returns, invocation.Syntax.GetLocation(), way.Facts, back)
            : null;
    }
}
