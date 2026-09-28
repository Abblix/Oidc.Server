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
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// A comment names the test or the data row it refers to instead of saying where it sits.
/// </summary>
/// <remarks>
/// A pointer by position stays true only until somebody inserts, moves or deletes a neighbor, and nothing
/// reports it: the build stays green and the reader follows it to whatever sits there now. A
/// <c>&lt;see cref="..."/&gt;</c> fails the build when its target is renamed or removed, and a row
/// described by its input stays true wherever it moves. The phrasings recognized here are the ones this
/// repository has used; a new phrasing outside them passes unnoticed, so this check keeps the known forms
/// from coming back and does not prove the absence of others.
/// </remarks>
public class PositionalPointerTests
{
    private const string Subject = @"(?:row|rows|case|cases|test|tests|theory|theories|fact|facts)";

    /// <summary>
    /// A subject followed by where it sits, or preceded by its order. The trailing guard keeps a compound
    /// such as <c>case-insensitive</c> from reading as the noun.
    /// </summary>
    private static readonly Regex Pointer = new(
        $@"\b(?:(?:the|this|that|these|those)\s+(?:\w+\s+)?{Subject}\s+(?:above|below)"
        + $@"|(?:above|below)\s+{Subject}"
        + $@"|(?:previous|preceding|next|following)\s+{Subject})\b(?![-\w])",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// The prefixes that open each line of a comment, removed so a phrase wrapped onto the next line of a
    /// doc comment reads as one.
    /// </summary>
    private static readonly Regex CommentMarkup = new(@"^\s*(?:///|//|/\*+|\*/|\*)?", RegexOptions.Multiline);

    /// <summary>
    /// Every comment in the source, as the compiler's lexer finds it, with its one-based line.
    /// </summary>
    /// <remarks>
    /// A run of <c>//</c> lines is one comment, as a doc comment is, so a phrase wrapped at a line break
    /// is read whole.
    /// </remarks>
    private static IEnumerable<(int Line, string Text)> Comments(string source)
    {
        var run = new List<SyntaxTrivia>();
        foreach (var token in CSharpSyntaxTree.ParseText(source).GetRoot().DescendantTokens())
        {
            foreach (var comment in Scan(token.LeadingTrivia, run))
                yield return comment;

            // Code between two comments ends the run as any other non-blank trivia does.
            foreach (var comment in Flush(run))
                yield return comment;

            foreach (var comment in Scan(token.TrailingTrivia, run))
                yield return comment;
        }

        foreach (var comment in Flush(run))
            yield return comment;
    }

    private static IEnumerable<(int Line, string Text)> Scan(SyntaxTriviaList trivia, List<SyntaxTrivia> run)
    {
        foreach (var item in trivia)
        {
            if (item.IsKind(SyntaxKind.SingleLineCommentTrivia))
            {
                run.Add(item);
                continue;
            }

            if (item.IsKind(SyntaxKind.WhitespaceTrivia) || item.IsKind(SyntaxKind.EndOfLineTrivia))
                continue;

            foreach (var comment in Flush(run))
                yield return comment;

            if (item.IsKind(SyntaxKind.MultiLineCommentTrivia)
                || item.IsKind(SyntaxKind.SingleLineDocumentationCommentTrivia)
                || item.IsKind(SyntaxKind.MultiLineDocumentationCommentTrivia))
            {
                yield return Read([item]);
            }
        }
    }

    private static IEnumerable<(int Line, string Text)> Flush(List<SyntaxTrivia> run)
    {
        if (run.Count == 0)
            yield break;

        var comment = Read(run);
        run.Clear();
        yield return comment;
    }

    private static (int Line, string Text) Read(IReadOnlyList<SyntaxTrivia> comment)
        => (comment[0].GetLocation().GetLineSpan().StartLinePosition.Line + 1,
            Regex.Replace(
                CommentMarkup.Replace(string.Join("\n", comment.Select(trivia => trivia.ToFullString())), string.Empty),
                @"\s+",
                " "));

    /// <summary>The pointers by position the source's comments contain, each with the line its comment starts on.</summary>
    private static IReadOnlyList<string> PointersIn(string source)
        => Comments(source)
            .SelectMany(comment => Pointer.Matches(comment.Text).Select(match => $"{comment.Line}: '{match.Value}'"))
            .ToArray();

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }

    [Fact]
    public void NoComment_PointsAtATestByItsPosition()
    {
        var root = RepositoryRoot();
        var excluded = new[] { "obj", "bin" };

        var sources = new[] { "src", "tests" }
            .SelectMany(area => Directory.EnumerateFiles(Path.Combine(root, area), "*.cs", SearchOption.AllDirectories))
            .Select(path => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(relative => !relative.Split('/').Intersect(excluded, StringComparer.Ordinal).Any())
            .ToArray();

        // The walk reached this very file, so an empty or misplaced walk cannot pass as a clean tree.
        Assert.Contains($"tests/Abblix.Oidc.Server.UnitTests/Architecture/{nameof(PositionalPointerTests)}.cs", sources);

        var problems = sources
            .SelectMany(relative => PointersIn(File.ReadAllText(Path.Combine(root, relative)))
                .Select(pointer => $"{relative}:{pointer}"))
            .ToArray();

        Assert.True(
            problems.Length == 0,
            "Name the test with <see cref=\"...\"/>, or describe the row by its input:"
            + Environment.NewLine + string.Join(Environment.NewLine, problems));
    }

    [Theory]
    [InlineData("/// <summary>The control for the row above.</summary>\nclass A {}", "1: 'the row above'")]
    [InlineData("class A {\n  // Without it the test below passes.\n}", "2: 'the test below'")]
    [InlineData("/// The control for the two rows above.\nclass A {}", "1: 'the two rows above'")]
    [InlineData("/// Without it, a validator would pass the row\n/// above, and nothing would say so.\nclass A {}", "1: 'the row above'")]
    [InlineData("class A {\n  // Falling back would make the row\n  // below pass anyway.\n}", "2: 'the row below'")]
    [InlineData("class A {\n  // Nothing on the row\n  int x;\n  // below here matters.\n}", null)]
    [InlineData("/* Together with the previous test, this pins the shape. */ class A {}", "1: 'previous test'")]
    [InlineData("/// Covered by the next test.\nclass A {}", "1: 'next test'")]
    [InlineData("/// Pinned by the above rows.\nclass A {}", "1: 'above rows'")]
    [InlineData("/// The control for <see cref=\"B\"/>.\nclass A {}", null)]
    [InlineData("// Under the previous case-insensitive comparison this passed.\nclass A {}", null)]
    [InlineData("class A { string s = \"the row above\"; }", null)]
    [InlineData("/// The row with an empty scope is refused.\nclass A {}", null)]
    public void APointerIsFoundInCommentsOnly(string source, string? expected)
        => Assert.Equal(expected, PointersIn(source).SingleOrDefault());
}
