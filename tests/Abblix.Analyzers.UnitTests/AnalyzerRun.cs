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
using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// Compiles a sample in memory and runs one analyzer over it, the way the compiler does in a build.
/// </summary>
internal static class AnalyzerRun
{
    /// <summary>
    /// The framework the tests run on, so a sample can use any type a real project here can.
    /// </summary>
    private static readonly ImmutableArray<MetadataReference> Framework =
    [
        .. ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            // The host may list an assembly the runtime folder does not carry; there is nothing to read.
            .Where(File.Exists)
            .Select(path => MetadataReference.CreateFromFile(path)),
    ];

    /// <summary>
    /// The diagnostics the analyzer reports over the sample, after the sample itself compiled clean.
    /// </summary>
    /// <remarks>
    /// A sample that does not compile would leave the analyzer looking at error symbols, and silence
    /// over a broken sample reads exactly like silence over a clean one.
    /// </remarks>
    public static async Task<ImmutableArray<Diagnostic>> DiagnosticsOf(DiagnosticAnalyzer analyzer, string source)
    {
        var compilation = CSharpCompilation.Create(
            "Sample",
            [CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Latest))],
            Framework,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var errors = compilation.GetDiagnostics(TestContext.Current.CancellationToken)
            .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)
            .ToArray();
        Assert.True(errors.Length == 0, string.Join(Environment.NewLine, errors.Select(error => error.ToString())));

        return await compilation
            .WithAnalyzers([analyzer])
            .GetAnalyzerDiagnosticsAsync(TestContext.Current.CancellationToken);
    }
}
