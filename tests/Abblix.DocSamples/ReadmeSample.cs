// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;

namespace Abblix.DocSamples;

/// <summary>
/// One enrolled README sample: the file it lives in, which of that file's C# blocks it is, and the
/// copy under <c>Samples/</c> that carries it as compiled source.
/// </summary>
/// <param name="Readme">The README's path relative to the repository root, with forward slashes.</param>
/// <param name="Index">Which fenced <c>csharp</c> block of that file, counting from zero.</param>
/// <param name="Copy">The file under <c>Samples/</c> that carries this sample as compiled source.</param>
/// <remarks>
/// Keyed by position rather than by a member identifier, unlike <see cref="DocSample"/>, because a
/// README block documents no member and has nothing else to be named by. The position is the weak part
/// of that key: inserting a block above an enrolled one silently re-points the enrolment at different
/// text. What catches it is the text comparison itself, which then finds two things that do not match,
/// rather than the key.
/// </remarks>
public sealed record ReadmeSample(string Readme, int Index, string Copy)
{
    public override string ToString() => $"{Readme}#{Index}";
}

/// <summary>
/// Reads the C# blocks out of the README files that ship with the packages.
/// </summary>
/// <remarks>
/// A README travels INSIDE the package, so its snippets are read by every consumer and compiled by
/// nothing: the quick-start called a constant from a library this one had deliberately stopped
/// depending on, and shipped that way through a whole release. Doc comments already have a gate
/// (<see cref="DocSampleReader"/>); this is the same idea over the other half of the prose.
/// <para>
/// The reader's project is what a snippet has to compile in, not this one. Two differences decide
/// everything: the reader has the packages and nothing else, and the web template hands them a set of
/// implicit usings that this test project does not have. So a copy declares those ambient namespaces
/// explicitly, in a marked region, and <c>ReadmeSampleTests</c> holds that region to the list the SDK
/// itself computes for a web project.
/// </para>
/// </remarks>
public static class ReadmeSampleReader
{
    /// <summary>
    /// The namespaces a project created from the ASP.NET Core web template imports without being asked.
    /// </summary>
    /// <remarks>
    /// Computed by MSBuild from the SDK this build is using, not written down here: the companion
    /// project <c>Abblix.DocSamples.WebTemplate</c> is a web-SDK project whose whole purpose is to let
    /// the SDK answer, and it writes <c>@(Using)</c> into an assembly attribute this reads.
    /// <para>
    /// A list frozen in source would be right on the day it was typed and would fail in the QUIET
    /// direction afterwards. An import ADDED to the template makes this row refuse a legitimate copy,
    /// which is loud; an import REMOVED - and <c>System.Net.Http.Json</c> is one that arrived by
    /// version - leaves a sample leaning on something the reader no longer has, with every row green.
    /// </para>
    /// </remarks>
    public static IReadOnlySet<string> TemplateImplicitUsings { get; } = ReadTemplateUsings();

    /// <summary>
    /// The template's imports, as the companion project's build recorded them.
    /// </summary>
    /// <exception cref="InvalidOperationException">The attribute is missing or empty, which means the
    /// companion project stopped being referenced or stopped writing it - and an empty set would make
    /// every ambient namespace look invented rather than make this row pass, so it is worth saying
    /// which of the two happened.</exception>
    private static IReadOnlySet<string> ReadTemplateUsings()
    {
        const string Companion = "Abblix.DocSamples.WebTemplate";

        Assembly companion;
        try
        {
            companion = Assembly.Load(Companion);
        }
        catch (FileNotFoundException notFound)
        {
            // By name rather than by path, so the runtime resolves it the way it resolves every other
            // reference. Missing means the project reference is gone, and saying so beats a set that
            // arrives empty and makes every ambient namespace look invented.
            throw new InvalidOperationException(
                $"{Companion} is not beside the tests, so the web template's imports cannot be read.",
                notFound);
        }

        var names = companion
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(metadata => metadata.Key == "WebTemplateImplicitUsings")
            .SelectMany(metadata => (metadata.Value ?? string.Empty).Split(
                ';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .ToHashSet(StringComparer.Ordinal);

        if (names.Count == 0)
        {
            throw new InvalidOperationException(
                "The companion project carries no implicit usings, which no web-SDK project does: its "
                + "attribute was renamed, or its item group moved above the SDK props it reads.");
        }

        return names;
    }

    /// <summary>
    /// Every README that ships with a package: the repository's own, and one per library.
    /// </summary>
    /// <remarks>
    /// Discovered rather than listed, so a new library's README is inside the count from its first
    /// commit instead of from whenever somebody remembers to add it.
    /// </remarks>
    public static IReadOnlyList<string> Files(string repositoryRoot)
    {
        // The repository's own README goes through the same existence check as the rest. Listed
        // unconditionally it would be reported as present by a method that had merely repeated the
        // literal back, and the row asserting it is there would have measured nothing.
        var candidates = Directory
            .EnumerateDirectories(Path.Combine(repositoryRoot, "src"))
            .Select(directory => Path.Combine(directory, "README.md"))
            .Prepend(Path.Combine(repositoryRoot, "README.md"));

        return candidates
            .Where(File.Exists)
            .Select(path => Path.GetRelativePath(repositoryRoot, path).Replace('\\', '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// The fenced C# blocks of one README, in the order they appear.
    /// </summary>
    /// <remarks>
    /// Only <c>csharp</c> fences: a <c>shell</c> block installing a package and a <c>json</c> block of
    /// settings are prose this gate has no compiler for, and counting them would inflate the remainder
    /// with work nobody can do.
    /// </remarks>
    public static IReadOnlyList<IReadOnlyList<string>> Blocks(string path)
    {
        var blocks = new List<IReadOnlyList<string>>();
        var current = new List<string>();
        var inside = false;

        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.Trim();

            if (!inside)
            {
                if (LanguageOf(trimmed) is "csharp" or "cs")
                {
                    inside = true;
                    current = [];
                }

                continue;
            }

            if (trimmed == "```")
            {
                inside = false;
                blocks.Add(current);
                continue;
            }

            current.Add(line);
        }

        if (inside)
        {
            throw new InvalidOperationException(
                $"{path} opens a C# block that is never closed, so its blocks cannot be counted.");
        }

        return blocks;
    }

    /// <summary>
    /// How many C# blocks the shipping READMEs carry between them.
    /// </summary>
    public static int BlockCount(string repositoryRoot) => Files(repositoryRoot)
        .Sum(file => Blocks(Path.Combine(repositoryRoot, file)).Count);

    /// <summary>
    /// The language a fence opens with, or null where the line opens no fence.
    /// </summary>
    /// <remarks>
    /// The first word after the backticks, because a fence may carry attributes after its language
    /// (<c>```csharp title="Program.cs"</c> renders in several site generators). Matching the whole line
    /// would leave such a block uncounted, and an uncounted block is exactly the silence the remainder
    /// count exists to break.
    /// </remarks>
    private static string? LanguageOf(string trimmed)
    {
        const string Fence = "```";

        if (!trimmed.StartsWith(Fence, StringComparison.Ordinal))
            return null;

        var info = trimmed[Fence.Length..].Trim();
        var space = info.IndexOf(' ');

        return space < 0 ? info : info[..space];
    }

    /// <summary>
    /// One enrolled sample, split into the imports it shows and the code under them.
    /// </summary>
    /// <exception cref="InvalidOperationException">The README has no block at that index, which means
    /// the enrolment points at text that has been moved or deleted and is guarding nothing.</exception>
    public static (IReadOnlyList<string> Usings, IReadOnlyList<string> Body) Read(
        string repositoryRoot, ReadmeSample sample)
    {
        var path = Path.Combine(repositoryRoot, sample.Readme.Replace('/', Path.DirectorySeparatorChar));
        var blocks = Blocks(path);

        if (sample.Index >= blocks.Count)
        {
            throw new InvalidOperationException(
                $"{sample} does not exist: that file carries {blocks.Count} C# block(s).");
        }

        return Split(blocks[sample.Index]);
    }

    /// <summary>
    /// The namespace a line imports, or null where the line is not a using directive at all.
    /// </summary>
    /// <remarks>
    /// A using STATEMENT opens a scope and belongs to the body; only a directive names a namespace, and
    /// the difference is the parenthesis rather than the keyword. Shared with the row that compares a
    /// copy's imports, which would otherwise read <c>using var scope = provider.CreateScope();</c> as a
    /// namespace and report a mismatch nobody could act on.
    /// </remarks>
    public static string? NamespaceOf(string line)
    {
        const string Directive = "using ";

        var trimmed = line.Trim();

        if (!trimmed.StartsWith(Directive, StringComparison.Ordinal) || !trimmed.EndsWith(';'))
            return null;

        return trimmed.Contains('(') ? null : trimmed[..^1][Directive.Length..].Trim();
    }

    /// <summary>
    /// Separates a block's leading <c>using</c> directives from the code they serve.
    /// </summary>
    /// <remarks>
    /// The two halves are checked differently and cannot be compared as one: a using directive is not
    /// legal inside the method body a copy wraps its sample in, and an import the snippet omits is a
    /// defect the body comparison cannot see. So the copy carries the imports at file scope, where the
    /// compiler resolves them, and the body between markers, where the text is compared.
    /// </remarks>
    private static (IReadOnlyList<string> Usings, IReadOnlyList<string> Body) Split(
        IReadOnlyList<string> block)
    {
        var usings = new List<string>();
        var index = 0;

        for (; index < block.Count; index++)
        {
            var line = block[index].Trim();

            if (line.Length == 0)
                continue;

            if (NamespaceOf(line) is not { } imported)
                break;

            usings.Add(imported);
        }

        return (usings, block.Skip(index).ToArray());
    }
}
