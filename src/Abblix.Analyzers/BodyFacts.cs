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
/// What one body of code touches: the properties and instance fields it names, the parameters it reads, the methods
/// and constructors it calls or hands on as a delegate, and the types it builds.
/// </summary>
internal sealed class BodyFacts
{
    /// <summary>The properties named, whether read or written.</summary>
    public HashSet<IPropertySymbol> Properties { get; } = new(SymbolEqualityComparer.Default);

    /// <summary>The methods and constructors called, or handed on as a delegate.</summary>
    public HashSet<IMethodSymbol> Calls { get; } = new(SymbolEqualityComparer.Default);

    /// <summary>The types built with <c>new</c>.</summary>
    public HashSet<ITypeSymbol> Created { get; } = new(SymbolEqualityComparer.Default);

    /// <summary>The instance fields named, whether read or written.</summary>
    public HashSet<IFieldSymbol> Fields { get; } = new(SymbolEqualityComparer.Default);

    /// <summary>The parameters read.</summary>
    public HashSet<IParameterSymbol> Parameters { get; } = new(SymbolEqualityComparer.Default);

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

                // A method handed on as a delegate, a nested mapper passed to a helper among them, runs as surely as
                // one called
                case IMethodReferenceOperation reference:
                    facts.Calls.Add(reference.Method.OriginalDefinition);
                    break;

                case IFieldReferenceOperation { Field.IsStatic: false } field:
                    facts.Fields.Add(field.Field.OriginalDefinition);
                    break;

                case IParameterReferenceOperation parameter:
                    facts.Parameters.Add(parameter.Parameter);
                    break;
            }
        }

        return facts;
    }

    /// <summary>
    /// The facts of a body that only calls <paramref name="method"/>.
    /// </summary>
    public static BodyFacts Calling(IMethodSymbol method)
    {
        var facts = new BodyFacts();
        facts.Calls.Add(method.OriginalDefinition);
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
        Fields.UnionWith(other.Fields);
        Parameters.UnionWith(other.Parameters);
    }
}
