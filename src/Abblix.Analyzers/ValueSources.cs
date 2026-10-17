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
/// Everything a value is computed from inside one method: the operations of the value itself, and, for each local
/// it reads, the operations of whatever that local was given.
/// </summary>
/// <remarks>
/// <para>
/// A call passes on what it is made on and what its arguments carry only when its result can hold text - a string,
/// a character, a URI, an object, a span, or a sequence of them - as <c>Trim</c> and <c>string.Join</c> do. A result
/// of any other type was looked up or computed by the server rather than copied: the registered client found by a
/// client id that was sent is the server's own record, and so is the type of a request. A constructor always passes
/// its arguments on, since what it builds usually keeps them.
/// </para>
/// <para>
/// A constant, a flag, a number and an enum member end the trail too: whether a code was sent, or how many values
/// were, is what the server observed, and no character a sender chose survives in it.
/// </para>
/// <para>
/// A local is given a value by its declaration, by an assignment, by a pattern that declares it, or as the variable
/// of a <c>foreach</c>, which takes its items from the collection; an <c>out var</c> takes it from the call it is
/// passed to, receiver and arguments alike. Each local is followed once, so a loop that feeds a local back into
/// itself ends.
/// </para>
/// </remarks>
internal sealed class ValueSources(Compilation compilation)
{
    private readonly INamedTypeSymbol? _task = compilation.GetTypeByMetadataName("System.Threading.Tasks.Task`1");
    private readonly INamedTypeSymbol? _valueTask = compilation.GetTypeByMetadataName("System.Threading.Tasks.ValueTask`1");
    private readonly INamedTypeSymbol? _uri = compilation.GetTypeByMetadataName("System.Uri");

    private readonly INamedTypeSymbol?[] _views =
    [
        compilation.GetTypeByMetadataName("System.Span`1"),
        compilation.GetTypeByMetadataName("System.ReadOnlySpan`1"),
        compilation.GetTypeByMetadataName("System.Memory`1"),
        compilation.GetTypeByMetadataName("System.ReadOnlyMemory`1"),
    ];

    /// <summary>The operations <paramref name="value"/> is computed from.</summary>
    public IEnumerable<IOperation> Of(IOperation value)
    {
        var root = value;
        while (root.Parent is not null)
            root = root.Parent;

        var followed = new HashSet<ILocalSymbol>(SymbolEqualityComparer.Default);
        var pending = new Stack<IOperation>();
        pending.Push(value);
        while (pending.Count > 0)
        {
            var operation = pending.Pop();
            if (CarriesNoText(operation))
                continue;

            yield return operation;

            foreach (var part in PartsOf(operation))
                pending.Push(part);

            foreach (var given in NotYetFollowed(operation, followed, root))
                pending.Push(given);
        }
    }

    /// <summary>
    /// Whether <paramref name="operation"/> yields something no sender's text survives in: a constant the compiler
    /// fixed, such as a <c>nameof</c>, or a flag, a number or an enum member - but not a character, since one
    /// character of a value is enough to carry a line break into the record. Whether a code was sent, or how many
    /// values were, is the server's own observation, though what it observed came from outside.
    /// </summary>
    private static bool CarriesNoText(IOperation operation)
    {
        if (operation.ConstantValue.HasValue)
            return true;

        var type = operation.Type is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T } nullable
            ? nullable.TypeArguments[0]
            : operation.Type;

        return type is { IsValueType: true, SpecialType: not SpecialType.System_Char }
               && (type.TypeKind == TypeKind.Enum || type.SpecialType != SpecialType.None);
    }

    private IEnumerable<IOperation> PartsOf(IOperation operation)
    {
        // Typed as the interface on purpose: the operation list the children come in is a struct whose default
        // value throws when enumerated, and an empty collection expression of that type would be one.
        IEnumerable<IOperation> none = [];
        return operation switch
        {
            IInvocationOperation invocation when !CanHoldText(invocation.Type) => none,
            _ => operation.ChildOperations,
        };
    }

    /// <summary>
    /// Whether a value of <paramref name="type"/> can hold text taken from what it was computed from, seen through a
    /// task, since an awaited call yields what its task holds.
    /// </summary>
    private bool CanHoldText(ITypeSymbol? type) => Awaited(type) switch
    {
        null => false,
        { SpecialType: SpecialType.System_String or SpecialType.System_Object } => true,
        IArrayTypeSymbol array => CanHoldText(array.ElementType),
        { SpecialType: SpecialType.System_Char } => true,
        INamedTypeSymbol named when Is(named, _uri) => true,
        INamedTypeSymbol { TypeArguments.Length: 1 } view when _views.Any(candidate => Is(view.OriginalDefinition, candidate))
            => CanHoldText(view.TypeArguments[0]),
        INamedTypeSymbol named => named.AllInterfaces.Append(named).Any(IsSequenceOfText),
        _ => false,
    };

    /// <summary>What a task of <paramref name="type"/> yields when awaited; the type itself otherwise.</summary>
    private ITypeSymbol? Awaited(ITypeSymbol? type)
    {
        if (type is not INamedTypeSymbol { TypeArguments.Length: 1 } generic)
            return type;

        var definition = generic.OriginalDefinition;
        return Is(definition, _task) || Is(definition, _valueTask) ? generic.TypeArguments[0] : type;
    }

    private bool IsSequenceOfText(INamedTypeSymbol type)
        => type.OriginalDefinition.SpecialType == SpecialType.System_Collections_Generic_IEnumerable_T
           && CanHoldText(type.TypeArguments[0]);

    /// <summary>
    /// What a local read by <paramref name="operation"/> was given, the first time it is met. A local that cannot
    /// hold text - an instant, a count, a record the server built - is not followed, since text that reached it on
    /// its way did not stay in it.
    /// </summary>
    private IEnumerable<IOperation> NotYetFollowed(
        IOperation operation,
        HashSet<ILocalSymbol> followed,
        IOperation root)
    {
        if (operation is not ILocalReferenceOperation { IsDeclaration: false, Local: var local })
            return [];

        return CanHoldText(local.Type) && followed.Add(local) ? GivenTo(local, root) : [];
    }

    private static IEnumerable<IOperation> GivenTo(ILocalSymbol local, IOperation root)
        => root.Descendants().SelectMany(operation => Given(operation, local));

    private static IEnumerable<IOperation> Given(IOperation operation, ILocalSymbol local) => operation switch
    {
        IVariableDeclaratorOperation declarator when Is(declarator.Symbol, local) => Declared(declarator),
        IAssignmentOperation { Target: ILocalReferenceOperation target } assignment when Is(target.Local, local)
            => [assignment.Value],
        IDeclarationPatternOperation pattern when Is(pattern.DeclaredSymbol, local) => Matched(pattern),
        IRecursivePatternOperation pattern when Is(pattern.DeclaredSymbol, local) => Matched(pattern),
        ILocalReferenceOperation { IsDeclaration: true, Parent: IDeclarationExpressionOperation declaration } reference
            when Is(reference.Local, local) => PassedOut(declaration),
        _ => [],
    };

    private static IEnumerable<IOperation> Declared(IVariableDeclaratorOperation declarator)
    {
        if (declarator.GetVariableInitializer() is { } initializer)
            return [initializer.Value];

        if (declarator.Parent is IForEachLoopOperation loop)
            return [loop.Collection];

        return [];
    }

    /// <summary>The receiver and the arguments of the call an <c>out var</c> is declared in.</summary>
    private static IEnumerable<IOperation> PassedOut(IDeclarationExpressionOperation declaration)
    {
        if (declaration.Parent is not IArgumentOperation { Parent: IInvocationOperation invocation })
            return [];

        var arguments = invocation.Arguments.Select(argument => argument.Value);
        return invocation.Instance is { } instance ? arguments.Prepend(instance) : arguments;
    }

    /// <summary>
    /// The value a pattern was matched against, or the member a property pattern read on the way to it.
    /// </summary>
    private static IEnumerable<IOperation> Matched(IPatternOperation pattern)
    {
        for (IOperation? current = pattern; current is not null; current = current.Parent)
        {
            switch (current)
            {
                case IPropertySubpatternOperation subpattern:
                    return [subpattern.Member];

                case IIsPatternOperation isPattern:
                    return [isPattern.Value];

                case ISwitchExpressionOperation switchExpression:
                    return [switchExpression.Value];

                case ISwitchOperation switchStatement:
                    return [switchStatement.Value];
            }
        }

        return [];
    }

    private static bool Is(ISymbol? symbol, ISymbol? other) => SymbolEqualityComparer.Default.Equals(symbol, other);
}
