// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Abblix.Analyzers;

/// <summary>
/// Refuses a conditional expression whose condition tests an enum against one of its members.
/// </summary>
/// <remarks>
/// <c>level == Level.Hard ? "hard" : "soft"</c> sends every other member to the second branch, including
/// one added later, and nothing reports it; a switch naming each member with a throwing default does.
/// A test for null or for a bool cannot grow and stays allowed, and so does a [Flags] enum, whose test
/// asks about one bit rather than picking a member.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class OneMemberConditionalAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic reported for every such conditional expression.</summary>
    public static readonly DiagnosticDescriptor Rule = new(
        id: "ABX1003",
        title: "A conditional expression picks by one member of an enum",
        messageFormat: "Replace the conditional with a switch on '{0}' that names every member and throws by default",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(Analyze, OperationKind.Conditional);
    }

    private static void Analyze(OperationAnalysisContext context)
    {
        var conditional = (IConditionalOperation)context.Operation;
        if (conditional.Syntax is not ConditionalExpressionSyntax
            || EnumTestedByMembers(conditional.Condition, context.Compilation) is not { } tested)
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(Rule, conditional.Syntax.GetLocation(), tested.Name));
    }

    // The enum the whole condition compares with its own members, or null when the condition asks something else.
    private static ITypeSymbol? EnumTestedByMembers(IOperation condition, Compilation compilation) => OwnEnum.Unwrapped(condition) switch
    {
        IUnaryOperation { OperatorKind: UnaryOperatorKind.Not } not => EnumTestedByMembers(not.Operand, compilation),
        IBinaryOperation binary => BinaryType(binary, compilation),
        IIsPatternOperation pattern => PatternMemberType(pattern.Pattern, compilation),
        _ => null,
    };

    private static readonly ImmutableHashSet<BinaryOperatorKind> Comparisons = ImmutableHashSet.Create(
        BinaryOperatorKind.Equals,
        BinaryOperatorKind.NotEquals,
        BinaryOperatorKind.LessThan,
        BinaryOperatorKind.LessThanOrEqual,
        BinaryOperatorKind.GreaterThan,
        BinaryOperatorKind.GreaterThanOrEqual);

    // A comparison with a member picks by it; both sides of && or || picking on one enum pick together.
    private static ITypeSymbol? BinaryType(IBinaryOperation binary, Compilation compilation)
    {
        if (binary.OperatorKind is BinaryOperatorKind.ConditionalOr or BinaryOperatorKind.ConditionalAnd)
            return Same(EnumTestedByMembers(binary.LeftOperand, compilation), EnumTestedByMembers(binary.RightOperand, compilation));

        return Comparisons.Contains(binary.OperatorKind)
            ? MemberType(binary.LeftOperand, compilation) ?? MemberType(binary.RightOperand, compilation)
            : null;
    }

    private static ITypeSymbol? PatternMemberType(IPatternOperation pattern, Compilation compilation) => pattern switch
    {
        IConstantPatternOperation constant => MemberType(constant.Value, compilation),
        IRelationalPatternOperation relational => MemberType(relational.Value, compilation),
        INegatedPatternOperation negated => PatternMemberType(negated.Pattern, compilation),
        IBinaryPatternOperation binary => BinaryPatternType(binary, compilation),
        _ => null,
    };

    // Both sides on one enum, or one side on the enum and the other on null, the way a nullable enum is tested.
    private static ITypeSymbol? BinaryPatternType(IBinaryPatternOperation binary, Compilation compilation)
    {
        var left = PatternMemberType(binary.LeftPattern, compilation);
        var right = PatternMemberType(binary.RightPattern, compilation);
        return (left, right) switch
        {
            ({ } l, null) when IsNullPattern(binary.RightPattern) => l,
            (null, { } r) when IsNullPattern(binary.LeftPattern) => r,
            _ => Same(left, right),
        };
    }

    private static bool IsNullPattern(IPatternOperation pattern) =>
        pattern is IConstantPatternOperation constant && OwnEnum.Unwrapped(constant.Value).ConstantValue is { HasValue: true, Value: null };

    private static ITypeSymbol? Same(ITypeSymbol? left, ITypeSymbol? right) =>
        left is not null && SymbolEqualityComparer.Default.Equals(left, right) ? left : null;

    // The own enum of a constant naming one of its members; null for anything else.
    private static ITypeSymbol? MemberType(IOperation operation, Compilation compilation)
    {
        var value = OwnEnum.Unwrapped(operation);
        return value.ConstantValue.HasValue ? OwnEnum.Of(value.Type, compilation) : null;
    }
}
