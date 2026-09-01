// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Xunit;

namespace Abblix.DocSamples;

/// <summary>
/// The gate over doc-comment code samples: the compiler checks the ones enrolled, and these rows check
/// that what it compiled is what the documentation says.
/// </summary>
/// <remarks>
/// The compilation is the assertion, and it happens before any of this runs - a sample naming a type
/// that was renamed away does not fail here, it fails the build. What these rows add is everything the
/// compiler cannot see: that the compiled copy still matches the doc comment, that the enrolment names
/// samples that exist, that the uncompiled remainder has not quietly grown, and that no stub written to
/// make a sample compile is shadowing a name the library actually ships.
/// </remarks>
public class DocSampleTests
{
    /// <summary>
    /// Every enrolled sample's text appears verbatim in the copy the compiler checked.
    /// </summary>
    /// <remarks>
    /// Without this the gate guards yesterday's text: a doc comment edited on its own leaves the copy
    /// compiling happily, which is precisely the state the samples were in before any of this existed.
    /// The copy carries a wrapper the sample does not - the ambient names a fragment calls into - so the
    /// comparison is containment rather than equality, line by line with leading whitespace ignored,
    /// since the wrapper indents what it encloses.
    /// </remarks>
    [Fact]
    public void EveryEnrolledSampleMatchesTheCopyTheCompilerChecked()
    {
        var root = RepositoryRoot();
        var drifted = new List<string>();

        foreach (var sample in Enrolment.Compiled)
        {
            var documented = DocSampleReader.Read(root, sample);
            var compiled = File.ReadAllLines(CopyOf(root, sample)).Select(line => line.Trim()).ToHashSet();

            var missing = documented
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !compiled.Contains(line))
                .ToArray();

            if (missing.Length > 0)
                drifted.Add($"{sample}: {missing.Length} line(s) not in the copy, first: {missing[0]}");
        }

        Assert.Empty(drifted);
    }

    /// <summary>
    /// The uncompiled remainder is the number the enrolment states, and no other.
    /// </summary>
    /// <remarks>
    /// A gate that covers four samples out of sixteen is honest only while the twelve are counted. This
    /// row is what turns "the rest is not covered yet" from a sentence in a comment into something that
    /// fails when a sample is added and nobody decides about it - in either direction, since enrolling
    /// one without moving the number fails too.
    /// </remarks>
    [Fact]
    public void TheUncompiledRemainderIsWhatTheEnrolmentSays()
    {
        var root = RepositoryRoot();
        var total = Directory
            .EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Sum(file => DocSampleReader.BlocksIn(File.ReadAllLines(file)).Count);

        // The control: a walk that stopped finding anything would report every sample as unenrolled and
        // look exactly like a codebase with no samples in it.
        Assert.True(total > Enrolment.Compiled.Count, $"the walk found {total} code block(s) in src/");

        Assert.Equal(Enrolment.Unenrolled, total - Enrolment.Compiled.Count);
    }

    /// <summary>
    /// No stub written to make a sample compile shadows a name the library ships.
    /// </summary>
    /// <remarks>
    /// The weak seam of the whole gate. A sample calls into the integrator's own half - a notification
    /// service, a helper - and that half has to be stubbed here or nothing compiles. A stub that happens
    /// to carry the name of something the library really ships would satisfy the compiler while hiding
    /// the very rename this exists to catch, and the build would stay green through it.
    /// </remarks>
    [Fact]
    public void NoStubShadowsATypeTheLibraryShips()
    {
        var shipped = typeof(Abblix.Oidc.Server.Features.UserAuthentication.AuthSession).Assembly
            .GetExportedTypes()
            .Select(type => type.Name)
            .ToHashSet(StringComparer.Ordinal);

        var stubs = typeof(DocSampleTests).Assembly
            .GetTypes()
            .Where(type => type.Namespace == "Abblix.DocSamples.Stubs")
            .Select(type => type.Name)
            .ToArray();

        // The control again: an empty stub set passes the assertion below and measures nothing.
        Assert.NotEmpty(stubs);

        Assert.DoesNotContain(stubs, shipped.Contains);
    }

    /// <summary>
    /// Where the compiled copy of a sample lives, read from the sources rather than from the output.
    /// </summary>
    /// <remarks>
    /// ONE file, which is what makes the comparison mean anything: a copy emitted to the output
    /// directory beside the compiled one would let the two disagree, and this row would then compare a
    /// doc comment against a file no compiler ever read.
    /// <para>
    /// Named from the WHOLE relative path with the separators flattened, not from the file name: two of
    /// the four enrolled samples live in files called <c>ServiceCollectionExtensions.cs</c>, so a name
    /// taken from the file alone collides, and the collision does not fail - it silently compares one
    /// sample against the other's copy and passes whenever they happen to share a line.
    /// </para>
    /// </remarks>
    private static string CopyOf(string repositoryRoot, DocSample sample) => Path.Combine(
        repositoryRoot,
        "tests",
        "Abblix.DocSamples",
        "Samples",
        FlatName(sample));

    /// <summary>
    /// The copy's file name: the sample's whole relative path with the separators flattened.
    /// </summary>
    private static string FlatName(DocSample sample)
    {
        var path = sample.Source.Replace('/', '_').Replace('\\', '_');
        return $"{path[..^".cs".Length]}.{sample.Index}.cs";
    }

    /// <summary>
    /// The repository root, found by walking up from the test assembly until the sources are underneath.
    /// </summary>
    /// <remarks>
    /// By a landmark rather than by a fixed number of parents, because the number changes with the
    /// target framework and the configuration and a wrong one reads as "the samples are all gone".
    /// </remarks>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(
            Path.GetDirectoryName(typeof(DocSampleTests).Assembly.Location)!);

        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException(
            "No directory above the test assembly contains src/, so the samples cannot be read at all.");
    }
}
