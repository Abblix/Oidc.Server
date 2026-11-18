// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// A conditional expression that picks by one member of an enum is refused in every spelling, and nothing else is.
/// </summary>
public class OneMemberConditionalAnalyzerTests
{
    private const string Level = "enum Level { Soft, Hard, Lifelong }\n";

    [Theory]
    [InlineData("string M(Level l) => l == Level.Hard ? \"h\" : \"s\";")]
    [InlineData("string M(Level l) => Level.Hard != l ? \"s\" : \"h\";")]
    [InlineData("string M(Level l) => l is Level.Hard ? \"h\" : \"s\";")]
    [InlineData("string M(Level l) => l is Level.Hard or Level.Lifelong ? \"h\" : \"s\";")]
    [InlineData("string M(Level l) => l is not Level.Hard ? \"s\" : \"h\";")]
    [InlineData("string M(Level l) => !(l == Level.Hard) ? \"s\" : \"h\";")]
    [InlineData("string M(Level l, string a, string b) => (l == Level.Hard)\n    ? a\n    : b;")]
    [InlineData("object? M(Level l) => l == Level.Hard ? new object() : null;")]
    [InlineData("string M(Level? l) => l == Level.Hard ? \"h\" : \"s\";")]
    [InlineData("string M(Level? l) => l is Level.Hard or null ? \"h\" : \"s\";")]
    [InlineData("string M(Level l) => l >= Level.Hard ? \"h\" : \"s\";")]
    [InlineData("string M(Level l) => l is >= Level.Hard ? \"h\" : \"s\";")]
    [InlineData("string M(Level l) => l == Level.Soft || l == Level.Hard ? \"low\" : \"high\";")]
    public async Task APickByOneMemberIsReported(string member)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(new OneMemberConditionalAnalyzer(), Level + "class A { " + member + " }");

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal(OneMemberConditionalAnalyzer.Rule.Id, diagnostic.Id);
    }

    /// <summary>A test for null, a bool, a number, a string or a bit cannot grow a member, and a switch is the cure itself.</summary>
    [Theory]
    [InlineData("string M(Level l) => l switch { Level.Soft => \"s\", Level.Hard or Level.Lifelong => \"h\", _ => throw new System.ArgumentOutOfRangeException(nameof(l)) };")]
    [InlineData("string M(object? o) => o is null ? \"none\" : \"some\";")]
    [InlineData("string M(bool b) => b ? \"y\" : \"n\";")]
    [InlineData("int M(int n) => n == 0 ? 1 : n;")]
    [InlineData("string M(string s) => s == \"a\" ? \"x\" : \"y\";")]
    [InlineData("string M(Level a, Level b) => a == b ? \"same\" : \"other\";")]
    [InlineData("string M(Level l, bool f) => l == Level.Hard && f ? \"h\" : \"s\";")]
    [InlineData("string M(Level l, bool f) => l == Level.Hard || f ? \"h\" : \"s\";")]
    [InlineData("string M(Level? l) => l is null ? \"none\" : \"some\";")]
    [InlineData("string M(Level l) { if (l == Level.Hard) return \"h\"; return \"s\"; }")]
    public async Task AnotherConditionIsNotReported(string member)
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(new OneMemberConditionalAnalyzer(), Level + "class A { " + member + " }"));

    /// <summary>A built neighbour of the same product is held to the rule, one of another product is not.</summary>
    [Theory]
    [InlineData("Acme.Domain", 1)]
    [InlineData("Other.Library", 0)]
    public async Task AnEnumOfABuiltNeighbourIsHeldByItsProduct(string library, int expected)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsAcross(
            new OneMemberConditionalAnalyzer(),
            (library, "public enum Level { Soft, Hard }"),
            ("Acme.App", "class A { string M(Level l) => l == Level.Hard ? \"h\" : \"s\"; }"));

        Assert.Equal(expected, diagnostics.Length);
    }

    [Fact]
    public async Task AnEnumFromAReferencedAssemblyIsNotReported()
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new OneMemberConditionalAnalyzer(),
            "class C { string M(System.DayOfWeek d) => d == System.DayOfWeek.Sunday ? \"weekend\" : \"weekday\"; }"));

    [Fact]
    public async Task AFlagsTestIsNotReported()
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new OneMemberConditionalAnalyzer(),
            "[System.Flags] enum Bits { None = 0, A = 1, B = 2 }\nclass C { string M(Bits b) => (b & Bits.A) == Bits.A ? \"a\" : \"-\"; }"));

    [Fact]
    public async Task GeneratedCodeIsNotReported()
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new OneMemberConditionalAnalyzer(),
            ("Service.g.cs", Level + "class A { string M(Level l) => l == Level.Hard ? \"h\" : \"s\"; }")));
}
