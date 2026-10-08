// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// A declaration carrying a second summary is refused, and one carrying one summary with other tags is not.
/// </summary>
public class OneSummaryAnalyzerTests
{
    /// <summary>
    /// Every summary of a declaration carrying more than one is reported, so each candidate to keep is shown.
    /// </summary>
    [Theory]
    [InlineData("class A\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    void M() { }\n}", 2)]
    [InlineData("class A\n{\n    /// <summary>Old.</summary>\n\n    /// <summary>Inserted.</summary>\n    const int X = 1;\n\n    void M() { }\n}", 2)]
    [InlineData("/// <summary>One.</summary>\n/// <summary/>\n/// <summary>Three.</summary>\nclass A { }", 3)]
    [InlineData("enum E\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    Value,\n}", 2)]
    [InlineData("class A\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    int x, y;\n}", 2)]
    [InlineData("class A\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    int P { get; set; }\n}", 2)]
    [InlineData("/// <summary>First.</summary>\n/// <summary>Second.</summary>\nrecord R(int X);", 2)]
    [InlineData("/// <summary>First.</summary>\n/// <summary>Second.</summary>\nclass C(int x) { public int X => x; }", 2)]
    public async Task EverySummaryOfADeclarationWithMoreThanOneIsReported(string source, int expected)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(new OneSummaryAnalyzer(), source);

        Assert.Equal(expected, diagnostics.Length);
        Assert.All(diagnostics, diagnostic => Assert.Equal(OneSummaryAnalyzer.Rule.Id, diagnostic.Id));
    }

    /// <summary>
    /// Each part of a partial method is a symbol of its own, read on its own: two summaries on the declaring part are
    /// reported, though the compiler keeps only the implementing part's, since they are text nobody will see.
    /// </summary>
    [Fact]
    public async Task TwoSummariesOnThePartialMethodsDeclaration_AreReported()
    {
        const string source =
            "partial class A\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    partial void M();\n\n" +
            "    /// <summary>Implemented.</summary>\n    partial void M() { }\n}";

        Assert.Equal(2, (await AnalyzerRun.DiagnosticsOf(new OneSummaryAnalyzer(), source)).Length);
    }

    /// <summary>
    /// A diagnostic marks the summary itself, not the declaration it documents.
    /// </summary>
    [Fact]
    public async Task ADiagnosticMarksItsSummary()
    {
        const string source = "class A\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    void M() { }\n}";

        var diagnostics = await AnalyzerRun.DiagnosticsOf(new OneSummaryAnalyzer(), source);

        Assert.Equal(
            ["<summary>First.</summary>", "<summary>Second.</summary>"],
            diagnostics.Select(diagnostic => source.Substring(diagnostic.Location.SourceSpan.Start, diagnostic.Location.SourceSpan.Length))
                .Order());
    }

    /// <summary>
    /// A partial type documented in two parts carries both summaries, which the compiler joins in the documentation
    /// file.
    /// </summary>
    [Fact]
    public async Task APartialTypeDocumentedInTwoParts_IsReportedInEach()
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(
            new OneSummaryAnalyzer(),
            ("A.cs", "/// <summary>One part.</summary>\npartial class A { }"),
            ("A.More.cs", "/// <summary>The other part.</summary>\npartial class A { }"));

        Assert.Equal(["A.cs", "A.More.cs"], diagnostics.Select(diagnostic => diagnostic.Location.SourceTree!.FilePath).Order());
    }

    /// <summary>
    /// A generated part's summary counts, since the compiler joins it to the others, and the finding is reported on
    /// the part somebody edits.
    /// </summary>
    [Fact]
    public async Task AGeneratedPartsSummary_IsCounted_AndReportedOnTheEditedPart()
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(
            new OneSummaryAnalyzer(),
            ("A.cs", "/// <summary>Written by hand.</summary>\npartial class A { }"),
            ("A.g.cs", "/// <summary>Written by the generator.</summary>\npartial class A { }"));

        Assert.Equal("A.cs", Assert.Single(diagnostics).Location.SourceTree!.FilePath);
    }

    [Theory]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    /// <remarks>More.</remarks>\n    void M() { }\n}")]
    [InlineData("/// <summary>Type.</summary>\nclass A\n{\n    /// <summary>Member.</summary>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    /// <example><code>/// &lt;summary&gt;</code></example>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    // <summary>Not documentation.</summary>\n    /// <summary>One.</summary>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    /// <x:summary xmlns:x=\"urn:x\">Not a summary.</x:summary>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    /// <remarks><para><summary>Nested.</summary></para></remarks>\n    void M() { }\n}")]
    [InlineData("partial class A\n{\n    /// <summary>Declared.</summary>\n    partial void M();\n\n    /// <summary>Implemented.</summary>\n    partial void M() { }\n}")]
    public async Task OneSummaryIsNotReported(string source)
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(new OneSummaryAnalyzer(), source));

    /// <summary>
    /// A declaration written by a generator alone keeps whatever its generator wrote: nobody edits that output.
    /// </summary>
    [Fact]
    public async Task GeneratedCodeIsNotReported()
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new OneSummaryAnalyzer(),
            ("Model.g.cs", "/// <summary>First.</summary>\n/// <summary>Second.</summary>\nclass A { }")));
}
