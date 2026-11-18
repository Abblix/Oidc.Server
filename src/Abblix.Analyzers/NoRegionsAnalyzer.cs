// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Abblix.Analyzers;

/// <summary>
/// Refuses a <c>#region</c> directive.
/// </summary>
/// <remarks>
/// A region folds code out of sight in the editor, so a reader skims past exactly the part somebody
/// thought worth grouping; a file that needs one to be readable needs splitting instead. Read from the
/// compiler's own directive trivia, so a region inside a method or behind other directives is found the
/// same way as one at the top level, and text that merely spells the word inside a string is not.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class NoRegionsAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic reported for every <c>#region</c> directive.</summary>
    public static readonly DiagnosticDescriptor Rule = new(
        id: "ABX1001",
        title: "A #region hides code",
        messageFormat: "Remove the #region: split the file or the type instead of folding part of it away",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // Generated code is left alone: generators such as the gRPC tooling emit regions of their own,
        // and nobody reads or edits that output.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxTreeAction(Analyze);
    }

    private static void Analyze(SyntaxTreeAnalysisContext context)
    {
        var regions = context.Tree.GetRoot(context.CancellationToken)
            .DescendantTrivia(descendIntoTrivia: true)
            .Where(trivia => trivia.IsKind(SyntaxKind.RegionDirectiveTrivia));

        foreach (var region in regions)
            context.ReportDiagnostic(Diagnostic.Create(Rule, region.GetLocation()));
    }
}
