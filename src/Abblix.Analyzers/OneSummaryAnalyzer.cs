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

namespace Abblix.Analyzers;

/// <summary>
/// Refuses a declaration documented with more than one <c>&lt;summary&gt;</c>.
/// </summary>
/// <remarks>
/// A member inserted between an existing summary and the member it documents takes that summary along with its
/// own, and the member it was taken from is left with none; a partial type documented in two parts carries both. The
/// compiler reports neither and writes every summary into the documentation file, so the published API reference
/// shows two texts on one declaration and, in the first case, nothing on the other. The summaries are counted per
/// declared symbol across all its parts, read from the documentation comment structure the compiler parses, so two
/// comment blocks, one after a blank line, count the same as one, and the word written inside a code sample or a
/// string does not count.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class OneSummaryAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic reported on every summary of a declaration that carries more than one.</summary>
    public static readonly DiagnosticDescriptor Rule = new(
        id: "ABX1006",
        title: "A declaration has more than one summary",
        messageFormat: "'{0}' carries {1} summaries across its declaration: keep the one that describes it",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // A declaration a generator writes alone is left to it, since nobody edits that output. A symbol declared by
        // hand too still carries its generated parts, whose summaries the compiler joins to the others, so they count,
        // and the finding lands on the parts somebody edits
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSymbolAction(
            Analyze,
            SymbolKind.NamedType,
            SymbolKind.Method,
            SymbolKind.Property,
            SymbolKind.Field,
            SymbolKind.Event);
    }

    private static void Analyze(SymbolAnalysisContext context)
    {
        var summaries = context.Symbol.DeclaringSyntaxReferences
            .Select(reference => DocumentedDeclarationOf(reference.GetSyntax(context.CancellationToken)))
            .OfType<SyntaxNode>()
            .SelectMany(SummariesOf)
            .ToArray();

        if (summaries.Length < 2)
            return;

        foreach (var summary in summaries)
        {
            context.ReportDiagnostic(
                Diagnostic.Create(Rule, summary.GetLocation(), context.Symbol.Name, summaries.Length));
        }
    }

    // A field or an event field shares its declaration, and the documentation on it, with the other variables it
    // declares, so the declaration is read for the first of them alone
    private static SyntaxNode? DocumentedDeclarationOf(SyntaxNode node) => node switch
    {
        VariableDeclaratorSyntax { Parent: VariableDeclarationSyntax { Parent: BaseFieldDeclarationSyntax field } } declarator
            => field.Declaration.Variables[0] == declarator ? field : null,
        _ => node,
    };

    private static IEnumerable<XmlNodeSyntax> SummariesOf(SyntaxNode declaration)
        => declaration.GetLeadingTrivia()
            .Select(trivia => trivia.GetStructure())
            .OfType<DocumentationCommentTriviaSyntax>()
            .SelectMany(comment => comment.Content)
            .Where(IsSummary);

    private static bool IsSummary(XmlNodeSyntax node) => node switch
    {
        XmlElementSyntax element => IsSummary(element.StartTag.Name),
        XmlEmptyElementSyntax empty => IsSummary(empty.Name),
        _ => false,
    };

    private static bool IsSummary(XmlNameSyntax name)
        => name.Prefix is null && name.LocalName.ValueText == "summary";
}
