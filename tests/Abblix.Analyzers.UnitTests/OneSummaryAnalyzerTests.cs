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
    [Theory]
    [InlineData("class A\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    void M() { }\n}", 1)]
    [InlineData("class A\n{\n    /// <summary>Old.</summary>\n\n    /// <summary>Inserted.</summary>\n    const int X = 1;\n\n    void M() { }\n}", 1)]
    [InlineData("/// <summary>One.</summary>\n/// <summary/>\n/// <summary>Three.</summary>\nclass A { }", 2)]
    [InlineData("enum E\n{\n    /// <summary>First.</summary>\n    /// <summary>Second.</summary>\n    Value,\n}", 1)]
    public async Task EveryExtraSummaryIsReported(string source, int expected)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(new OneSummaryAnalyzer(), source);

        Assert.Equal(expected, diagnostics.Length);
        Assert.All(diagnostics, diagnostic => Assert.Equal(OneSummaryAnalyzer.Rule.Id, diagnostic.Id));
    }

    [Theory]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    /// <remarks>More.</remarks>\n    void M() { }\n}")]
    [InlineData("/// <summary>Type.</summary>\nclass A\n{\n    /// <summary>Member.</summary>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    /// <summary>One.</summary>\n    /// <example><code>/// &lt;summary&gt;</code></example>\n    void M() { }\n}")]
    [InlineData("class A\n{\n    // <summary>Not documentation.</summary>\n    /// <summary>One.</summary>\n    void M() { }\n}")]
    public async Task OneSummaryIsNotReported(string source)
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(new OneSummaryAnalyzer(), source));

    /// <summary>
    /// Generated code keeps whatever its generator wrote: nobody edits that output, and it is not published.
    /// </summary>
    [Fact]
    public async Task GeneratedCodeIsNotReported()
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new OneSummaryAnalyzer(),
            ("Model.g.cs", "/// <summary>First.</summary>\n/// <summary>Second.</summary>\nclass A { }")));
}
