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
/// Refuses a declaration documented with more than one <c>&lt;summary&gt;</c>.
/// </summary>
/// <remarks>
/// A member inserted between an existing summary and the member it documents takes that summary along with its
/// own, and the member it was taken from is left with none. The compiler reports neither, and the published API
/// reference then shows the wrong text on one member and nothing on the other. Read from the documentation
/// comment structure the compiler parses, so a summary split across two comment blocks, one after a blank line,
/// is counted the same way, and the word written inside a code sample or a string is not.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class OneSummaryAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic reported on every summary after the first one of a declaration.</summary>
    public static readonly DiagnosticDescriptor Rule = new(
        id: "ABX1006",
        title: "A declaration has more than one summary",
        messageFormat: "Keep one <summary>: a second one usually belongs to the declaration below or above this one",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // Generated code is left alone: nobody reads or edits that output, and its documentation is not published.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxTreeAction(Analyze);
    }

    private static void Analyze(SyntaxTreeAnalysisContext context)
    {
        // A documentation comment is leading trivia of the declaration's first token, so every summary that token
        // carries, in however many comment blocks, documents one declaration.
        var tokens = context.Tree.GetRoot(context.CancellationToken)
            .DescendantTokens()
            .Where(token => token.HasStructuredTrivia);

        foreach (var token in tokens)
        {
            var extraSummaries = token.LeadingTrivia
                .Select(trivia => trivia.GetStructure())
                .OfType<DocumentationCommentTriviaSyntax>()
                .SelectMany(comment => comment.Content)
                .Where(IsSummary)
                .Skip(1);

            foreach (var summary in extraSummaries)
                context.ReportDiagnostic(Diagnostic.Create(Rule, summary.GetLocation()));
        }
    }

    private static bool IsSummary(XmlNodeSyntax node) => node switch
    {
        XmlElementSyntax element => IsSummary(element.StartTag.Name),
        XmlEmptyElementSyntax empty => IsSummary(empty.Name),
        _ => false,
    };

    private static bool IsSummary(XmlNameSyntax name)
        => name.Prefix is null && name.LocalName.ValueText == "summary";
}
