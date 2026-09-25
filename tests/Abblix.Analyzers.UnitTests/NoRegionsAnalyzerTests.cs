// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// A <c>#region</c> is refused wherever the compiler reads one, and only there.
/// </summary>
public class NoRegionsAnalyzerTests
{
    [Theory]
    [InlineData("#region Top\nclass A { }\n#endregion", 1)]
    [InlineData("class A\n{\n    #region Members\n    int x;\n    #endregion\n}", 1)]
    [InlineData("class A\n{\n    void M()\n    {\n        #region Body\n        #endregion\n    }\n}", 1)]
    [InlineData("#region Outer\nclass A\n{\n    #region Inner\n    #endregion\n}\n#endregion", 2)]
    [InlineData("#if true\n#region Behind\n#endregion\n#endif\nclass A { }", 1)]
    public async Task EveryRegionIsReported(string source, int expected)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(new NoRegionsAnalyzer(), source);

        Assert.Equal(expected, diagnostics.Length);
        Assert.All(diagnostics, diagnostic => Assert.Equal(NoRegionsAnalyzer.Rule.Id, diagnostic.Id));
    }

    [Theory]
    [InlineData("class A { string s = \"#region not a directive\"; }")]
    [InlineData("class A { } // #region in a comment")]
    [InlineData("class A { }")]
    public async Task TextThatOnlySpellsTheWordIsNotReported(string source)
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(new NoRegionsAnalyzer(), source));
}
