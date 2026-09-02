// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.UserAuthentication;
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
    /// Every enrolled sample and its copy carry the same lines, in the same order.
    /// </summary>
    /// <remarks>
    /// Without this the gate guards yesterday's text: a doc comment edited on its own leaves the copy
    /// compiling happily, which is precisely the state the samples were in before any of this existed.
    /// <para>
    /// EQUALITY, which took three attempts to get right and each attempt was measured. Set membership
    /// let the two body lines be SWAPPED, leaving documentation that calls a method before the
    /// registration it configures. Requiring an unbroken run in order caught that and still let a line be
    /// DELETED, because a shorter run is still a run. What a sample is has to be marked, or "the same
    /// lines" has no second list to compare against - so each copy delimits its sample with
    /// <c>// &lt;sample&gt;</c>, and this compares the two lists outright.
    /// </para>
    /// <para>
    /// Compared with leading whitespace ignored and blank lines dropped, because the wrapper that
    /// supplies the ambient names a fragment calls into also indents what it encloses.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryEnrolledSampleMatchesTheCopyTheCompilerChecked()
    {
        var root = RepositoryRoot();
        var drifted = new List<string>();

        foreach (var sample in Enrolment.Compiled)
        {
            var documented = Meaningful(DocSampleReader.Read(root, sample));
            var compiled = Meaningful(MarkedRegion(CopyOf(root, sample)));

            if (!documented.SequenceEqual(compiled))
            {
                drifted.Add(
                    $"{sample}: the doc comment has {documented.Count} line(s), the copy's marked sample "
                    + $"has {compiled.Count}, and they are not the same lines in the same order");
            }
        }

        Assert.Empty(drifted);
    }

    /// <summary>
    /// The lines of a copy between its sample markers.
    /// </summary>
    /// <remarks>
    /// The markers are the copy's way of saying which of its lines are the sample and which are the
    /// wrapper. A copy without them is a copy this row cannot check, so their absence is a failure
    /// rather than an empty region that would compare equal to nothing and pass.
    /// </remarks>
    private static IReadOnlyList<string> MarkedRegion(string copyPath)
    {
        var lines = File.ReadAllLines(copyPath);
        var begin = Array.FindIndex(lines, line => line.Trim() == "// <sample>");
        var end = Array.FindIndex(lines, line => line.Trim() == "// </sample>");

        if (begin < 0 || end < begin)
            throw new InvalidOperationException($"{copyPath} carries no // <sample> region.");

        return lines[(begin + 1)..end];
    }

    /// <summary>
    /// The lines that carry meaning: trimmed, with blank ones dropped.
    /// </summary>
    private static IReadOnlyList<string> Meaningful(IEnumerable<string> lines)
        => lines.Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();

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
    /// No stub written to make a sample compile shadows a name any referenced library ships.
    /// </summary>
    /// <remarks>
    /// The weak seam of the whole gate. A sample calls into the integrator's own half - a notification
    /// service, a helper - and that half has to be stubbed here or nothing compiles. A stub that happens
    /// to carry the name of something a library really ships would satisfy the compiler while hiding the
    /// very rename this exists to catch, and the build would stay green through it.
    /// <para>
    /// EVERY referenced library, taken from what this assembly references rather than from a type that
    /// happened to be at hand. Reading one assembly covered a third of the surface: <c>CustodianHeldKeys</c>
    /// ships from Abblix.Jwt and is used by two of the four copies, and a stub of that name passed.
    /// </para>
    /// <para>
    /// And every type, not only the exported ones - an internal name a sample reaches through
    /// <c>InternalsVisibleTo</c> is shadowed just as quietly.
    /// </para>
    /// </remarks>
    [Fact]
    public void NoStubShadowsATypeTheLibraryShips()
    {
        var shipped = typeof(DocSampleTests).Assembly
            .GetReferencedAssemblies()
            .Where(reference => reference.Name?.StartsWith("Abblix.", StringComparison.Ordinal) == true)
            .Select(Assembly.Load)
            .SelectMany(assembly => assembly.GetTypes())
            .Select(type => type.Name)
            .ToHashSet(StringComparer.Ordinal);

        var stubs = typeof(DocSampleTests).Assembly
            .GetTypes()
            .Where(type => type.Namespace == "Abblix.DocSamples.Stubs")
            .Select(type => type.Name)
            .ToArray();

        // Three controls. An empty stub set passes the assertion below and measures nothing, and a
        // shipped set that lost a library would do the same - which is exactly how this row was weak
        // before, reading one assembly out of three.
        Assert.NotEmpty(stubs);
        Assert.Contains(nameof(CustodianHeldKeys), shipped);
        Assert.Contains(nameof(AuthSession), shipped);

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
