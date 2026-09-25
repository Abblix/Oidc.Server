// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// A type deriving from <c>TimeProvider</c> is refused under any name and by any route, and nothing
/// else is.
/// </summary>
public class NoHomemadeClockAnalyzerTests
{
    [Theory]
    [InlineData("class SteadyClock : System.TimeProvider { }", "SteadyClock")]
    [InlineData("class Tick<T> : System.TimeProvider { }", "Tick")]
    [InlineData("file sealed class Local : System.TimeProvider { }", "Local")]
    [InlineData("class Outer { internal sealed class Nested : System.TimeProvider { } }", "Nested")]
    public async Task ADirectSubclassIsReported(string source, string expected)
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(new NoHomemadeClockAnalyzer(), source);

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal(NoHomemadeClockAnalyzer.Rule.Id, diagnostic.Id);
        Assert.Contains($"'{expected}'", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A clock one step removed from <c>TimeProvider</c> is still a clock, and so is its base.
    /// </summary>
    [Fact]
    public async Task EveryTypeInAChainIsReported()
    {
        var diagnostics = await AnalyzerRun.DiagnosticsOf(new NoHomemadeClockAnalyzer(), """
            abstract class ClockBase : System.TimeProvider { }
            sealed class ManualClock : ClockBase { }
            """);

        Assert.Equal(
            ["ClockBase", "ManualClock"],
            diagnostics.Select(diagnostic => diagnostic.Location.SourceTree!
                    .GetText(TestContext.Current.CancellationToken)
                    .ToString(diagnostic.Location.SourceSpan))
                .Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("class Consumer { System.TimeProvider clock = System.TimeProvider.System; }")]
    [InlineData("class Other : System.Exception { }")]
    [InlineData("class TimeProviderHolder { }")]
    public async Task ATypeThatIsNotAClockIsNotReported(string source)
        => Assert.Empty(await AnalyzerRun.DiagnosticsOf(new NoHomemadeClockAnalyzer(), source));
}
