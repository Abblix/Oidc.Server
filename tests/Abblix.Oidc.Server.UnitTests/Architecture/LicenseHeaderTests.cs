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
/// Every source file carries the license its package ships under.
/// </summary>
/// <remarks>
/// This repository ships some packages under Apache-2.0 and the rest under the commercial agreement, and
/// the build does not read comments. A file added from a neighbour in another package, or moved between
/// packages, keeps the header it came with, and nothing else reports it.
/// </remarks>
public class LicenseHeaderTests
{
    private const string Apache = "Apache-2.0";
    private const string Proprietary = "LicenseRef-Abblix-EULA";

    private const string HeaderTitle = "Abblix OIDC Server Library";
    private const string Copyright = "Copyright (c) Abblix LLP";
    private const string Identifier = "SPDX-License-Identifier:";

    /// <summary>The wording of the header every file carried before the packages were relicensed.</summary>
    private const string SupersededNotice = "LICENSE RESTRICTIONS";

    /// <summary>
    /// Opened under Apache-2.0 at the 2.4 release. Everything else stays under the agreement, including
    /// the key-management satellites of the opened <c>Abblix.Jwt</c>: a permissive license carries
    /// nothing over to what depends on it.
    /// </summary>
    private static readonly HashSet<string> OpenPackages = new(StringComparer.Ordinal)
    {
        "Abblix.Utils",
        "Abblix.DependencyInjection",
        "Abblix.Jwt",
        "Abblix.SecurityEvents",
        "Abblix.SecurityEvents.CAEP",
        "Abblix.SecurityEvents.RISC",
        "Abblix.SecurityEvents.MinimalApi",
    };

    /// <summary>
    /// A test project is named after what it exercises, so stripping the suffix yields the package whose
    /// license it follows.
    /// </summary>
    private static readonly string[] TestSuffixes = [".E2E.TestHost", ".E2E.Tests", ".UnitTests"];

    /// <summary>
    /// Opened as well: an Apache-2.0 fork of the opened packages cannot run their suites without these
    /// helpers.
    /// </summary>
    private static readonly HashSet<string> OpenTestDirectories = new(StringComparer.Ordinal) { "Shared" };

    /// <summary>The license a file under <c>src/</c> or <c>tests/</c> is expected to declare.</summary>
    /// <param name="relativePath">The path from the repository root, with forward slashes.</param>
    private static string ExpectedFor(string relativePath)
    {
        var parts = relativePath.Split('/');
        var directory = parts.Length > 1 ? parts[1] : parts[0];

        if (parts[0] == "tests")
        {
            if (OpenTestDirectories.Contains(directory))
                return Apache;

            if (TestSuffixes.FirstOrDefault(suffix => directory.EndsWith(suffix, StringComparison.Ordinal))
                is { } suffix)
            {
                directory = directory[..^suffix.Length];
            }
        }

        return OpenPackages.Contains(directory) ? Apache : Proprietary;
    }

    /// <summary>
    /// The comments before a file's first token, which is what the file header is.
    /// </summary>
    /// <remarks>
    /// Read by the compiler's own lexer, so a comment is whatever the compiler says is one, however the
    /// file is laid out: a directive ahead of the header, a block comment, or none at all.
    /// </remarks>
    private static IReadOnlyList<string> HeaderComments(string source)
        => SyntaxFactory.ParseLeadingTrivia(source)
            .Where(trivia => trivia.IsKind(SyntaxKind.SingleLineCommentTrivia)
                             || trivia.IsKind(SyntaxKind.MultiLineCommentTrivia))
            .Select(trivia => trivia.ToString())
            .ToArray();

    /// <summary>
    /// The one thing wrong with a file's header, or null.
    /// </summary>
    /// <remarks>
    /// The first failure wins: a file carrying the superseded notice has nothing to say about which
    /// identifier it declares.
    /// </remarks>
    private static string? ProblemWith(string source, string relativePath)
    {
        var comments = HeaderComments(source);

        if (comments.Any(comment => comment.Contains(SupersededNotice, StringComparison.Ordinal)))
            return "carries the superseded proprietary notice";

        var titles = comments.Count(comment => comment.Contains(HeaderTitle, StringComparison.Ordinal));
        if (titles > 1)
            return $"the license header appears {titles} times";

        if (!comments.Any(comment => comment.Contains(Copyright, StringComparison.Ordinal)))
            return "no copyright line naming Abblix LLP";

        var declared = comments
            .Select(comment => comment.IndexOf(Identifier, StringComparison.Ordinal) is var at and >= 0
                ? comment[(at + Identifier.Length)..].Trim()
                : null)
            .FirstOrDefault(value => value is not null);

        if (declared is null)
            return "no SPDX-License-Identifier in the file header";

        var expected = ExpectedFor(relativePath);
        return declared == expected ? null : $"declares {declared}, package expects {expected}";
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
    public void EverySourceFile_CarriesTheHeaderItsPackageExpects()
    {
        var root = RepositoryRoot();
        var excluded = new[] { "obj", "bin" };

        var sources = new[] { "src", "tests" }
            .SelectMany(area => Directory.EnumerateFiles(Path.Combine(root, area), "*.cs", SearchOption.AllDirectories))
            .Select(path => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(relative => !relative.Split('/').Intersect(excluded, StringComparer.Ordinal).Any())
            .ToArray();

        // The walk reached this very file, so an empty or misplaced walk cannot pass as a clean tree.
        Assert.Contains($"tests/Abblix.Oidc.Server.UnitTests/Architecture/{nameof(LicenseHeaderTests)}.cs", sources);

        var problems = sources
            .Select(relative => (relative, why: ProblemWith(File.ReadAllText(Path.Combine(root, relative)), relative)))
            .Where(found => found.why is not null)
            .Select(found => $"{found.relative}: {found.why}")
            .ToArray();

        Assert.True(problems.Length == 0, string.Join(Environment.NewLine, problems));
    }

    [Theory]
    [InlineData("src/Abblix.Jwt/Any.cs", Apache)]
    [InlineData("src/Abblix.Jwt.Vault/Any.cs", Proprietary)]
    [InlineData("src/Abblix.Oidc.Server/Any.cs", Proprietary)]
    [InlineData("tests/Abblix.Jwt.UnitTests/Any.cs", Apache)]
    [InlineData("tests/Abblix.SecurityEvents.E2E.Tests/Any.cs", Apache)]
    [InlineData("tests/Abblix.Oidc.Server.E2E.TestHost/Any.cs", Proprietary)]
    [InlineData("tests/Shared/Any.cs", Apache)]
    public void ThePackageDecidesTheLicense(string relativePath, string expected)
        => Assert.Equal(expected, ExpectedFor(relativePath));

    private const string Open = "// Abblix OIDC Server Library\n// SPDX-FileCopyrightText: Copyright (c) Abblix LLP\n";

    [Theory]
    [InlineData(Open + "// SPDX-License-Identifier: Apache-2.0\n\nnamespace A;", null)]
    [InlineData("#nullable enable\n" + Open + "// SPDX-License-Identifier: Apache-2.0\nnamespace A;", null)]
    [InlineData(Open + "// SPDX-License-Identifier: LicenseRef-Abblix-EULA\nnamespace A;", "declares LicenseRef-Abblix-EULA, package expects Apache-2.0")]
    [InlineData(Open + "namespace A;", "no SPDX-License-Identifier in the file header")]
    [InlineData("// Abblix OIDC Server Library\n// SPDX-License-Identifier: Apache-2.0\nnamespace A;", "no copyright line naming Abblix LLP")]
    [InlineData(Open + "// SPDX-License-Identifier: Apache-2.0\n" + Open + "namespace A;", "the license header appears 2 times")]
    [InlineData("// LICENSE RESTRICTIONS\n" + Open + "// SPDX-License-Identifier: Apache-2.0\nnamespace A;", "carries the superseded proprietary notice")]
    [InlineData("namespace A;\n" + Open + "// SPDX-License-Identifier: Apache-2.0\n", "no copyright line naming Abblix LLP")]
    public void AHeaderIsJudgedByTheCommentsBeforeTheFirstToken(string source, string? expected)
        => Assert.Equal(expected, ProblemWith(source, "src/Abblix.Jwt/Any.cs"));
}
