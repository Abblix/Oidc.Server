// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// explicitly, in a marked region, and <c>ReadmeSampleTests</c> holds that region to the template's own
/// list - measured from a generated <c>GlobalUsings.g.cs</c> rather than recalled.
/// </para>
/// </remarks>
public static class ReadmeSampleReader
{
    /// <summary>
    /// The namespaces a project created from the ASP.NET Core web template imports without being asked.
    /// </summary>
    /// <remarks>
    /// Read out of the <c>GlobalUsings.g.cs</c> that <c>dotnet new web</c> produces on the target
    /// framework, so it states what the reader's compiler sees rather than what anybody remembers of it.
    /// A snippet may lean on these without showing them; anything else it needs it has to show.
    /// </remarks>
    public static IReadOnlySet<string> TemplateImplicitUsings { get; } = new HashSet<string>(
        StringComparer.Ordinal)
    {
        "Microsoft.AspNetCore.Builder",
        "Microsoft.AspNetCore.Hosting",
        "Microsoft.AspNetCore.Http",
        "Microsoft.AspNetCore.Routing",
        "Microsoft.Extensions.Configuration",
        "Microsoft.Extensions.DependencyInjection",
        "Microsoft.Extensions.Hosting",
        "Microsoft.Extensions.Logging",
        "System",
        "System.Collections.Generic",
        "System.IO",
        "System.Linq",
        "System.Net.Http",
        "System.Net.Http.Json",
        "System.Threading",
        "System.Threading.Tasks",
    };

    /// <summary>
    /// Every README that ships with a package: the repository's own, and one per library.
    /// </summary>
    /// <remarks>
    /// Discovered rather than listed, so a new library's README is inside the count from its first
    /// commit instead of from whenever somebody remembers to add it.
    /// </remarks>
    public static IReadOnlyList<string> Files(string repositoryRoot)
    {
        var files = new List<string> { "README.md" };

        files.AddRange(Directory
            .EnumerateDirectories(Path.Combine(repositoryRoot, "src"))
            .Select(directory => Path.Combine(directory, "README.md"))
            .Where(File.Exists)
            .Select(path => Path.GetRelativePath(repositoryRoot, path).Replace('\\', '/')));

        return files.OrderBy(path => path, StringComparer.Ordinal).ToArray();
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
                if (trimmed is "```csharp" or "```cs")
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

            if (!line.StartsWith("using ", StringComparison.Ordinal) || !line.EndsWith(';'))
                break;

            // A using STATEMENT opens a scope and belongs to the body; only a directive names a
            // namespace, and the difference is the parenthesis rather than the keyword.
            if (line.Contains('('))
                break;

            usings.Add(line[..^1]["using ".Length..].Trim());
        }

        return (usings, block.Skip(index).ToArray());
    }
}
