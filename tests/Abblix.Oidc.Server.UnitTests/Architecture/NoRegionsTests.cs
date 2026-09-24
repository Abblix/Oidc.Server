// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// No source file carries a <c>#region</c>.
/// </summary>
/// <remarks>
/// A region folds code out of sight in the editor and says nothing the compiler can hold anyone to; its
/// title is a comment that stops describing the code it hides on the first move. Found through the
/// compiler's own syntax tree, so a directive is whatever the compiler reads as one.
/// </remarks>
public class NoRegionsTests
{
    private static IReadOnlyList<int> RegionLines(string source)
    {
        var tree = CSharpSyntaxTree.ParseText(source);
        return tree.GetRoot()
            .DescendantTrivia(descendIntoTrivia: true)
            .Where(trivia => trivia.IsKind(SyntaxKind.RegionDirectiveTrivia))
            .Select(trivia => tree.GetLineSpan(trivia.Span).StartLinePosition.Line + 1)
            .ToArray();
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }

    [Fact]
    public void NoSourceFileCarriesARegion()
    {
        var root = RepositoryRoot();
        var excluded = new[] { "obj", "bin" };

        var sources = new[] { "src", "tests" }
            .SelectMany(area => Directory.EnumerateFiles(Path.Combine(root, area), "*.cs", SearchOption.AllDirectories))
            .Select(path => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(relative => !relative.Split('/').Intersect(excluded, StringComparer.Ordinal).Any())
            .ToArray();

        // The walk reached this very file, so an empty or misplaced walk cannot pass as a clean tree.
        Assert.Contains($"tests/Abblix.Oidc.Server.UnitTests/Architecture/{nameof(NoRegionsTests)}.cs", sources);

        var regions = sources
            .SelectMany(relative => RegionLines(File.ReadAllText(Path.Combine(root, relative)))
                .Select(line => $"{relative}({line})"))
            .ToArray();

        Assert.True(regions.Length == 0, string.Join(Environment.NewLine, regions));
    }

    [Theory]
    [InlineData("class A\n{\n#region Members\n    int x;\n#endregion\n}", 3)]
    [InlineData("class A\n{\n    #region\n}\n", 3)]
    [InlineData("#region Header\nnamespace A;\n#endregion\n", 1)]
    public void ARegionIsFoundWhereverTheCompilerReadsOne(string source, int line)
        => Assert.Equal([line], RegionLines(source));

    [Theory]
    [InlineData("class A\n{\n    // #region is only mentioned here\n}")]
    [InlineData("class A\n{\n    string s = \"#region\";\n}")]
    public void TextThatOnlyMentionsARegionIsNotOne(string source)
        => Assert.Empty(RegionLines(source));
}
