// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Xunit;

namespace Abblix.DocSamples;

/// <summary>
/// The gate over the code samples that ship inside the packages, in the READMEs.
/// </summary>
/// <remarks>
/// The same bargain as <see cref="DocSampleTests"/>: the compiler is the assertion, and it has already
/// run by the time any row here does. What these rows add is what the compiler cannot see - that the
/// compiled copy still says what the README says, that the copy leans only on names the reader's own
/// project would have, and that the uncompiled remainder has not quietly grown.
/// </remarks>
public class ReadmeSampleTests
{
    /// <summary>
    /// Every enrolled README sample and its copy carry the same lines, in the same order.
    /// </summary>
    /// <remarks>
    /// Without this the copy compiles on happily while the README is edited around it, which is the
    /// state every README in the repository was in until this project reached them.
    /// </remarks>
    [Fact]
    public void EveryEnrolledSampleMatchesTheCopyTheCompilerChecked()
    {
        var root = RepositoryRoot();
        var drifted = new List<string>();

        foreach (var sample in Enrolment.ReadmeCompiled)
        {
            var (_, documented) = ReadmeSampleReader.Read(root, sample);
            var compiled = Meaningful(Region(CopyOf(root, sample), "sample"));

            if (!Meaningful(documented).SequenceEqual(compiled))
            {
                drifted.Add(
                    $"{sample}: the README block and the copy's marked sample are not the same lines "
                    + "in the same order");
            }
        }

        Assert.Empty(drifted);
    }

    /// <summary>
    /// A copy imports what its README shows, plus only what the web template would have imported anyway.
    /// </summary>
    /// <remarks>
    /// The row that catches the defect this whole file was written for. A snippet compiles here because
    /// the test project references every library at once; the reader has the packages the README told
    /// them to install and the template's implicit usings, and nothing else. An import the copy adds
    /// silently is an import the reader does not have, so the copy would build and their paste would
    /// not - and an import the README shows but the copy drops is the mirror of it, a directive nobody
    /// ever resolved.
    /// <para>
    /// Which is not a hypothetical: the quick-start carried <c>using Microsoft.IdentityModel.Tokens;</c>
    /// for a constant that had moved into this library, and <c>Abblix.Jwt</c> states in its own package
    /// description that it depends on no such package.
    /// </para>
    /// </remarks>
    [Fact]
    public void ACopyImportsWhatTheReadmeShowsAndOnlyAmbientNamesBesides()
    {
        var root = RepositoryRoot();
        var wrong = new List<string>();

        foreach (var sample in Enrolment.ReadmeCompiled)
        {
            var (documented, _) = ReadmeSampleReader.Read(root, sample);
            var copy = CopyOf(root, sample);

            var ambient = Namespaces(Region(copy, "ambient"));
            var declared = Namespaces(File.ReadAllLines(copy)).Except(ambient, StringComparer.Ordinal);

            if (!documented.OrderBy(name => name, StringComparer.Ordinal)
                    .SequenceEqual(declared.OrderBy(name => name, StringComparer.Ordinal)))
            {
                wrong.Add(
                    $"{sample}: the README shows [{string.Join(", ", documented)}] and the copy declares "
                    + $"[{string.Join(", ", declared)}] outside its ambient region");
            }

            var invented = ambient
                .Where(name => !ReadmeSampleReader.TemplateImplicitUsings.Contains(name))
                .ToArray();

            if (invented.Length > 0)
            {
                wrong.Add(
                    $"{sample}: the copy calls [{string.Join(", ", invented)}] ambient, and the web "
                    + "template imports no such namespace, so the reader would have to write it");
            }
        }

        Assert.Empty(wrong);
    }

    /// <summary>
    /// The uncompiled remainder is the number the enrolment states, and no other.
    /// </summary>
    /// <remarks>
    /// A snippet added to a README is a snippet nobody has decided about, and this is what makes that
    /// decision arrive: enrolling one without moving the number fails just as loudly as adding one.
    /// </remarks>
    [Fact]
    public void TheUncompiledRemainderIsWhatTheEnrolmentSays()
    {
        var root = RepositoryRoot();
        var files = ReadmeSampleReader.Files(root);

        // Two controls. A root found wrong, or a src/ that stopped being walked, reports zero blocks and
        // reads exactly like a repository whose READMEs carry no code - which is the shape every quiet
        // failure of this kind takes.
        Assert.Contains("README.md", files);
        Assert.True(files.Count > 1, "only the repository's own README was found, so src/ went unread");

        var total = ReadmeSampleReader.BlockCount(root);
        Assert.True(total > Enrolment.ReadmeCompiled.Count, $"the READMEs carry {total} C# block(s)");

        Assert.Equal(Enrolment.ReadmeUnenrolled, total - Enrolment.ReadmeCompiled.Count);
    }

    /// <summary>
    /// The lines of a copy between a pair of markers.
    /// </summary>
    /// <remarks>
    /// A copy without the markers is a copy nothing can check, so their absence is a failure rather than
    /// an empty region - which would compare equal to nothing and pass.
    /// </remarks>
    private static IReadOnlyList<string> Region(string copyPath, string marker)
    {
        var lines = File.ReadAllLines(copyPath);
        var begin = Array.FindIndex(lines, line => line.Trim() == $"// <{marker}>");
        var end = Array.FindIndex(lines, line => line.Trim() == $"// </{marker}>");

        if (begin < 0 || end < begin)
            throw new InvalidOperationException($"{copyPath} carries no // <{marker}> region.");

        return lines[(begin + 1)..end];
    }

    /// <summary>
    /// The namespaces named by the using directives among these lines.
    /// </summary>
    private static IReadOnlyList<string> Namespaces(IEnumerable<string> lines) => lines
        .Select(line => line.Trim())
        .Where(line => line.StartsWith("using ", StringComparison.Ordinal) && line.EndsWith(';'))
        .Select(line => line[..^1]["using ".Length..].Trim())
        .ToArray();

    /// <summary>
    /// The lines that carry meaning: trimmed, with blank ones dropped.
    /// </summary>
    private static IReadOnlyList<string> Meaningful(IEnumerable<string> lines)
        => lines.Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();

    /// <summary>
    /// Where the compiled copy of a README sample lives.
    /// </summary>
    private static string CopyOf(string repositoryRoot, ReadmeSample sample) => Path.Combine(
        repositoryRoot, "tests", "Abblix.DocSamples", "Samples", sample.Copy);

    /// <summary>
    /// The repository root, found by walking up from the test assembly until the sources are underneath.
    /// </summary>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(
            Path.GetDirectoryName(typeof(ReadmeSampleTests).Assembly.Location)!);

        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException(
            "No directory above the test assembly contains src/, so the READMEs cannot be read at all.");
    }
}
