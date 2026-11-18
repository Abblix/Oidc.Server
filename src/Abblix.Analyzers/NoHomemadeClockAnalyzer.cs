// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Abblix.Analyzers;

/// <summary>
/// Refuses a type that derives from <c>System.TimeProvider</c>.
/// </summary>
/// <remarks>
/// Production code takes <c>TimeProvider.System</c> and tests take the <c>FakeTimeProvider</c> that
/// Microsoft.Extensions.TimeProvider.Testing ships. A hand-written clock answers a reader who meets it
/// with rules somebody wrote once for one test: it advances, or fails to, and its timers fire, or do not,
/// in ways nobody else's clock does. Found by what a type derives from, directly or through another
/// class, so a copy under any name, generic, nested or file-local, is found as well. The banned-API
/// analyzer cannot refuse it, because a subclass calls the <c>TimeProvider</c> constructor implicitly and
/// that analyzer does not see an implicit base call.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class NoHomemadeClockAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic reported for every type deriving from <c>System.TimeProvider</c>.</summary>
    public static readonly DiagnosticDescriptor Rule = new(
        id: "ABX1002",
        title: "A type declares its own TimeProvider",
        messageFormat: "'{0}' derives from TimeProvider: use TimeProvider.System, or FakeTimeProvider in a test",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // Generated code is checked too: a clock is a clock whoever wrote it, and a partial class whose
        // generated part is reported first would otherwise hide the base class written by hand.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            // A compilation that cannot see TimeProvider cannot declare a subclass of it.
            if (start.Compilation.GetTypeByMetadataName("System.TimeProvider") is { } timeProvider)
                start.RegisterSymbolAction(symbol => Analyze(symbol, timeProvider), SymbolKind.NamedType);
        });
    }

    private static void Analyze(SymbolAnalysisContext context, INamedTypeSymbol timeProvider)
    {
        var type = (INamedTypeSymbol)context.Symbol;
        for (var baseType = type.BaseType; baseType is not null; baseType = baseType.BaseType)
        {
            if (!SymbolEqualityComparer.Default.Equals(baseType.OriginalDefinition, timeProvider))
                continue;

            context.ReportDiagnostic(Diagnostic.Create(Rule, type.Locations[0], type.Name));
            return;
        }
    }
}
