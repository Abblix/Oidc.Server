// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Abblix.Analyzers;

/// <summary>
/// Refuses a switch on an enum of the product being built that leaves some of its members to the default.
/// </summary>
/// <remarks>
/// A member added later then lands in the default arm, which answers for it without anyone deciding;
/// naming every member makes the addition fail the build at each switch, and the default can only throw.
/// An enum of another product is exempt (<see cref="OwnEnum"/>), since dispatching on a foreign token and refusing
/// the rest - a JSON token type, say - is the correct shape there; so is a [Flags] enum. A guarded arm names its
/// member: whoever wrote it decided that member, and a member added later is still named nowhere.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class EveryMemberSwitchAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic reported for every switch that leaves members unnamed.</summary>
    public static readonly DiagnosticDescriptor Rule = new(
        id: "ABX1004",
        title: "A switch on an enum leaves members to the default",
        messageFormat: "Name every member of '{0}' in the switch; missing: {1}",
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
        context.RegisterOperationAction(AnalyzeExpression, OperationKind.SwitchExpression);
        context.RegisterOperationAction(AnalyzeStatement, OperationKind.Switch);
    }

    private static void AnalyzeExpression(OperationAnalysisContext context)
    {
        var expression = (ISwitchExpressionOperation)context.Operation;
        var named = expression.Arms.SelectMany(arm => NamedBy(arm.Pattern));
        Report(context, expression.Value, named);
    }

    private static void AnalyzeStatement(OperationAnalysisContext context)
    {
        var statement = (ISwitchOperation)context.Operation;
        var named = statement.Cases
            .SelectMany(@case => @case.Clauses)
            .SelectMany(clause => clause switch
            {
                ISingleValueCaseClauseOperation single => Constant(single.Value),
                IPatternCaseClauseOperation pattern => NamedBy(pattern.Pattern),
                _ => [],
            });
        Report(context, statement.Value, named);
    }

    private static void Report(OperationAnalysisContext context, IOperation value, IEnumerable<decimal> named)
    {
        if (OwnEnum.Of(OwnEnum.Unwrapped(value).Type, context.Compilation) is not { } enumType)
            return;

        var covered = new HashSet<decimal>(named);
        var missing = enumType.GetMembers()
            .OfType<IFieldSymbol>()
            .Where(field => field.HasConstantValue && OwnEnum.Numeric(field.ConstantValue) is { } number && !covered.Contains(number))
            .Select(field => field.Name)
            .ToArray();

        if (missing.Length > 0)
            context.ReportDiagnostic(Diagnostic.Create(Rule, context.Operation.Syntax.GetLocation(), enumType.Name, string.Join(", ", missing)));
    }

    // The member values a pattern names outright; a pattern that matches by anything else names none.
    private static IEnumerable<decimal> NamedBy(IPatternOperation pattern) => pattern switch
    {
        IConstantPatternOperation constant => Constant(constant.Value),
        IBinaryPatternOperation { OperatorKind: BinaryOperatorKind.Or } or => NamedBy(or.LeftPattern).Concat(NamedBy(or.RightPattern)),
        _ => [],
    };

    private static IEnumerable<decimal> Constant(IOperation operation) =>
        OwnEnum.Unwrapped(operation).ConstantValue is { HasValue: true } constant && OwnEnum.Numeric(constant.Value) is { } number
            ? [number]
            : [];
}
