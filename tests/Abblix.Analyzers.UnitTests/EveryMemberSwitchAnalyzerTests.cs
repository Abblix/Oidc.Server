// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// A switch on an enum of this compilation names every member, in an expression and in a statement alike.
/// </summary>
public class EveryMemberSwitchAnalyzerTests
{
    private const string Level = "enum Level { Soft, Hard, Lifelong }\n";

    [Theory]
    [InlineData("string M(Level l) => l switch { Level.Soft => \"s\", _ => \"h\" };")]
    [InlineData("string M(Level l) => l switch { Level.Soft => \"s\", Level.Hard => \"h\", _ => throw new System.ArgumentOutOfRangeException(nameof(l)) };")]
    [InlineData("string M(Level l, bool f) => l switch { Level.Soft => \"s\", Level.Hard when f => \"h\", _ => \"rest\" };")]
    [InlineData("string M(Level? l) => l switch { Level.Soft => \"s\", null => \"n\", _ => \"h\" };")]
    [InlineData("string M(Level l) { switch (l) { case Level.Soft: return \"s\"; default: return \"h\"; } }")]
    [InlineData("string M(Level l) { switch (l) { case Level.Soft or Level.Hard: return \"s\"; } return \"x\"; }")]
    public async Task ASwitchLeavingMembersIsReported(string member)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(new EveryMemberSwitchAnalyzer(), Level + "class A { " + member + " }");

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal(EveryMemberSwitchAnalyzer.Rule.Id, diagnostic.Id);
    }

    [Theory]
    [InlineData("string M(Level l) => l switch { Level.Soft => \"s\", Level.Hard or Level.Lifelong => \"h\", _ => throw new System.ArgumentOutOfRangeException(nameof(l)) };")]
    [InlineData("string M(Level l) { switch (l) { case Level.Soft: return \"s\"; case Level.Hard: case Level.Lifelong: return \"h\"; default: throw new System.ArgumentOutOfRangeException(nameof(l)); } }")]
    [InlineData("string M(System.DayOfWeek d) => d switch { System.DayOfWeek.Sunday => \"w\", _ => throw new System.ArgumentOutOfRangeException(nameof(d)) };")]
    [InlineData("string M(int n) => n switch { 0 => \"zero\", _ => \"other\" };")]
    [InlineData("string M(Level l, bool f) => l switch { Level.Soft => \"s\", Level.Hard when f => \"h\", Level.Lifelong => \"l\", _ => \"rest\" };")]
    [InlineData("string M(object o) => o switch { string => \"s\", _ => \"o\" };")]
    public async Task ASwitchNamingEveryMemberOrNotOnOwnEnumIsNotReported(string member)
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(new EveryMemberSwitchAnalyzer(), Level + "class A { " + member + " }"));

    [Fact]
    public async Task TheMessageNamesTheMissingMembers()
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(
            new EveryMemberSwitchAnalyzer(),
            Level + "class A { string M(Level l) => l switch { Level.Soft => \"s\", _ => \"h\" }; }");

        Assert.Contains("Hard, Lifelong", Assert.Single(diagnostics).GetMessage(System.Globalization.CultureInfo.InvariantCulture));
    }

    [Theory]
    [InlineData("string M(Level l) { switch (l) { case Level.Soft or Level.Hard: case Level.Lifelong: return \"s\"; default: throw new System.ArgumentOutOfRangeException(nameof(l)); } }")]
    [InlineData("string M(Bytes b) => b switch { 0 => \"p\", Bytes.Q => \"q\", _ => throw new System.ArgumentOutOfRangeException(nameof(b)) };")]
    public async Task EverySpellingOfAMemberCounts(string member)
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new EveryMemberSwitchAnalyzer(),
            Level + "enum Bytes : byte { P, Q }\nclass A { " + member + " }"));

    [Fact]
    public async Task GeneratedCodeIsNotReported()
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new EveryMemberSwitchAnalyzer(),
            ("Service.g.cs", Level + "class A { string M(Level l) => l switch { Level.Soft => \"s\", _ => \"h\" }; }")));

    /// <summary>A built neighbour of the same product is held to the rule, one of another product is not.</summary>
    [Theory]
    [InlineData("Acme.Domain", 1)]
    [InlineData("Other.Library", 0)]
    public async Task AnEnumOfABuiltNeighbourIsHeldByItsProduct(string library, int expected)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsAcross(
            new EveryMemberSwitchAnalyzer(),
            (library, "public enum Level { Soft, Hard }"),
            ("Acme.App", "class A { string M(Level l) => l switch { Level.Soft => \"s\", _ => \"h\" }; }"));

        Assert.Equal(expected, diagnostics.Length);
    }

    [Fact]
    public async Task AFlagsSwitchIsNotReported()
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(
            new EveryMemberSwitchAnalyzer(),
            "[System.Flags] enum Bits { None = 0, A = 1, B = 2 }\nclass C { string M(Bits b) => b switch { Bits.A => \"a\", _ => \"-\" }; }"));
}
