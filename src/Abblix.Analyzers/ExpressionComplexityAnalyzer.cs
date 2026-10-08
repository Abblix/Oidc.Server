// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Abblix.Analyzers;

/// <summary>
/// Refuses an expression that joins more conditions with <c>&amp;&amp;</c>, <c>||</c> and <c>?:</c> than a reader
/// holds at once.
/// </summary>
/// <remarks>
/// Takes the place of Sonar's S1067, which counts <c>or</c> and <c>and</c> inside a pattern as well. Those name the
/// cases one arm answers alike, which a reader takes in as a list rather than as conditions to combine, and counting
/// them forces an exhaustive switch apart into arms that repeat one answer. A part that is not itself an expression
/// (an argument, a switch arm, a guard, an interpolation hole), a lambda body and each member an initializer sets
/// are judged as expressions of their own.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ExpressionComplexityAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The most conditional operators one expression may hold, as in S1067.</summary>
    public const int MaxOperators = 3;

    /// <summary>The diagnostic reported for an expression over the ceiling.</summary>
    public static readonly DiagnosticDescriptor Rule = new(
        id: "ABX1005",
        title: "An expression joins too many conditions",
        messageFormat: "The expression holds {0} conditional operators, over the ceiling of {1}: name a part of it",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // Generated code is left alone: nobody reads or edits that output.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxTreeAction(Analyze);
    }

    private static void Analyze(SyntaxTreeAnalysisContext context)
    {
        var expressions = context.Tree.GetRoot(context.CancellationToken)
            .DescendantNodes()
            .OfType<ExpressionSyntax>()
            .Where(StartsAnExpression);

        foreach (var expression in expressions)
        {
            // The walk stops at a nested expression but still yields it, so its own operator is left for it to count
            var operators = expression
                .DescendantNodesAndSelf(node => node == expression || !StartsAnExpression(node))
                .Count(node => IsConditionalOperator(node) && (node == expression || !StartsAnExpression(node)));

            if (operators > MaxOperators)
                context.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation(), operators, MaxOperators));
        }
    }

    // An expression nested in another belongs to it; a lambda body and each member an initializer sets stand alone
    private static bool StartsAnExpression(SyntaxNode node)
        => node is ExpressionSyntax &&
           node.Parent is not ExpressionSyntax or AnonymousFunctionExpressionSyntax or InitializerExpressionSyntax;

    private static bool IsConditionalOperator(SyntaxNode node)
        => node.IsKind(SyntaxKind.LogicalAndExpression) ||
           node.IsKind(SyntaxKind.LogicalOrExpression) ||
           node.IsKind(SyntaxKind.ConditionalExpression);
}
