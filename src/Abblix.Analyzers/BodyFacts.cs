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
/// What one body of code touches: the properties it names, the methods and constructors it calls, and the types it
/// builds.
/// </summary>
internal sealed class BodyFacts
{
    /// <summary>The properties named, whether read or written.</summary>
    public HashSet<IPropertySymbol> Properties { get; } = new(SymbolEqualityComparer.Default);

    /// <summary>The methods and constructors called.</summary>
    public HashSet<IMethodSymbol> Calls { get; } = new(SymbolEqualityComparer.Default);

    /// <summary>The types built with <c>new</c>.</summary>
    public HashSet<ITypeSymbol> Created { get; } = new(SymbolEqualityComparer.Default);

    /// <summary>
    /// The facts of the operations under <paramref name="roots"/>, lambdas and local functions inside them included.
    /// </summary>
    public static BodyFacts Of(IEnumerable<IOperation> roots)
    {
        var facts = new BodyFacts();
        foreach (var operation in roots.SelectMany(root => root.DescendantsAndSelf()))
        {
            switch (operation)
            {
                case IPropertyReferenceOperation reference:
                    facts.Properties.Add(reference.Property.OriginalDefinition);
                    break;

                case IObjectCreationOperation { Type: { } type } creation:
                    facts.Created.Add(type.OriginalDefinition);
                    if (creation.Constructor is { } constructor)
                        facts.Calls.Add(constructor.OriginalDefinition);
                    break;

                case IInvocationOperation invocation:
                    facts.Calls.Add(invocation.TargetMethod.OriginalDefinition);
                    break;
            }
        }

        return facts;
    }

    /// <summary>
    /// Adds the facts of <paramref name="other"/> to these.
    /// </summary>
    public void Add(BodyFacts other)
    {
        Properties.UnionWith(other.Properties);
        Calls.UnionWith(other.Calls);
        Created.UnionWith(other.Created);
    }
}
