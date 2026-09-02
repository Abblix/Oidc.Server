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
            var documented = Meaningful(DocSampleReader.Read(sample));
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
    /// Every file under <c>Samples/</c> is named by an enrolment.
    /// </summary>
    /// <remarks>
    /// A copy nobody enrolled still COMPILES, so it looks like coverage and is none: nothing compares it
    /// to a doc comment, and its text drifts freely while the build stays green. The remainder count
    /// cannot see it either - that is derived from the documentation, and an orphan copy corresponds to
    /// no documented sample at all.
    /// </remarks>
    [Fact]
    public void EveryCopyIsNamedByAnEnrolment()
    {
        var directory = Path.Combine(
            RepositoryRoot(), "tests", "Abblix.DocSamples", "Samples");

        var files = Directory.EnumerateFiles(directory, "*.cs").Select(Path.GetFileName).ToArray();

        // The control: the directory really was read, so an empty listing does not pass as "no orphans".
        Assert.NotEmpty(files);

        var enrolled = Enrolment.Compiled.Select(sample => sample.Copy).ToHashSet(StringComparer.Ordinal);

        var orphans = files.Where(file => !enrolled.Contains(file!)).ToArray();

        // Named, not merely counted: a bare "filter matched in collection" sends the reader to find the
        // file by hand, and every other row in this file explains itself.
        Assert.True(orphans.Length == 0, $"under Samples/ but enrolled by nothing: {string.Join(", ", orphans)}");
    }

    /// <summary>
    /// The uncompiled remainder is the number the enrolment states, and no other.
    /// </summary>
    /// <remarks>
    /// A gate that covers four samples out of sixteen is honest only while the twelve are counted.
    /// This row is what turns "the rest is not covered yet" from a sentence in a comment into something
    /// that fails when a sample is added and nobody decides about it - in either direction, since
    /// enrolling one without moving the number fails too.
    /// <para>
    /// The number has moved twice, and each move was a fact about the INSTRUMENT rather than about the
    /// samples. Twelve to fourteen when the count stopped coming from a hand-written parser, which could
    /// not see a one-line block or a tag with an attribute; then fourteen back to twelve when the reader
    /// stopped counting a primary-constructor type's comment twice.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheUncompiledRemainderIsWhatTheEnrolmentSays()
    {
        // Two controls. Documentation files that stopped being found would report every sample as
        // unenrolled and read exactly like a codebase with no samples in it - and finding only ONE
        // library's file would do the same more quietly, which is the shape every narrowing here has
        // taken so far.
        // Every project this one references must have put its documentation here - a library that stops
        // emitting documentation is a library this gate stops reading, and it would otherwise be a
        // quieter pass rather than a failure.
        //
        // Not the same thing as the reference list being intact, which is what the number below used to
        // be read as. Dropping a reference has two outcomes, both measured, and REACHABILITY decides
        // which - not whether the library carries a sample. Still reachable through another reference:
        // nothing changes, and nothing needs to, since its documentation is still here to be read.
        // Abblix.Oidc.Server itself is in that class, arriving through Mvc, AspNetCore and MinimalApi,
        // though it carries two enrolled samples. Reachable no longer: its documentation goes with it and the
        // count below sees that, or a Samples/ copy names its types and the compiler refuses first.
        var documented = DocSampleReader.Documents()
            .Select(document => (string?)document.Root!.Element("assembly")!.Element("name")!)
            .ToHashSet(StringComparer.Ordinal);

        var referenced = DocSampleReader.ReferencedProjects();

        // The control, and it is not ceremony: this list is written by MSBuild into an assembly
        // attribute, so a renamed key or an item group placed above the references it reads yields an
        // EMPTY list, and every Assert.All below then passes over nothing. Measured - renaming the key
        // alone left all four rows green. The count rather than only emptiness, because a list that
        // shrank is the same failure wearing a smaller number.
        Assert.Equal(Enrolment.References, referenced.Count);

        // A bare NAME, not a path. The first version of this took the file name out of an Include path
        // with Path.GetFileNameWithoutExtension, which on Linux does not treat a backslash as a
        // separator - so the whole path came back as the name and every item below failed, green here
        // and red on the runner. The list comes from MSBuild now and cannot carry a separator, and this
        // says so on the machine where the platform difference is invisible.
        Assert.All(referenced, project => Assert.DoesNotContain('/', project));
        Assert.All(referenced, project => Assert.DoesNotContain('\\', project));

        Assert.All(referenced, project => Assert.Contains(project, documented));

        // And the SIZE of what is beside the output, which is a different guarantee: the one above
        // cannot see a reference disappear, since a shorter list is a shorter loop. This one names the
        // number of documentation files the gate reads - however each arrived - so a library that stops
        // being built into this output is a failure rather than a quieter pass.
        Assert.Equal(Enrolment.Libraries, documented.Count);

        var total = DocSampleReader.BlockCount();
        Assert.True(total > Enrolment.Compiled.Count, $"the documents carry {total} code block(s)");

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
    /// Every Abblix assembly sitting BESIDE this one, which is what actually ships together. Two earlier
    /// versions were narrower and both looked complete: one type's assembly covered a third of the
    /// surface, and <c>GetReferencedAssemblies</c> covered five of the seven then referenced, because
    /// that is the reference table the compiler EMITTED - trimmed to assemblies whose types the test
    /// code happens to touch. Sixteen projects are referenced now; what the assertion below reads is
    /// <see cref="Enrolment.Libraries"/> against the number of ASSEMBLIES beside the output - a third
    /// quantity again, and one that agrees with the other two only while BOTH halves hold: every
    /// referenced project emits documentation, and nothing arrives beside the output that this project
    /// does not name. Drop a transitively-reachable reference and the three read 15, 16 and 16. The
    /// five-of-seven is history.
    /// Measured, it omitted <c>Abblix.DependencyInjection</c> and <c>Abblix.SecurityEvents</c>, both
    /// shipped packages, and a stub named after a type in either passed.
    /// </para>
    /// <para>
    /// And every type, not only the exported ones - an internal name a sample reaches through
    /// <c>InternalsVisibleTo</c> is shadowed just as quietly.
    /// </para>
    /// </remarks>
    [Fact]
    public void NoStubShadowsATypeTheLibraryShips()
    {
        var beside = Path.GetDirectoryName(typeof(DocSampleTests).Assembly.Location)!;
        var libraries = Directory
            .EnumerateFiles(beside, "Abblix.*.dll")
            .Where(path => Path.GetFileNameWithoutExtension(path) != "Abblix.DocSamples")
            .Select(Assembly.LoadFrom)
            .ToArray();

        var shipped = libraries
            .SelectMany(assembly => assembly.GetTypes())
            .Select(type => type.Name)
            .ToHashSet(StringComparer.Ordinal);

        var stubs = typeof(DocSampleTests).Assembly
            .GetTypes()
            .Where(type => type.Namespace == "Abblix.DocSamples.Stubs")
            .Select(type => type.Name)
            .ToArray();

        // Controls, because every way this row has been weak was a SILENT narrowing of what it compares
        // against. An empty stub set passes the assertion below and measures nothing; so would a shipped
        // set that lost a library, which is what both earlier versions did.
        //
        // An EQUALITY, not a floor. A floor of seven read as a control and was not one: measured, nine
        // of the SIXTEEN references could be dropped with every row here still green, because those
        // nine carry no sample today. And it would never surface later either - a library whose
        // documentation has left the output is invisible to the count, so a sample added there is not
        // seen at all. The equality is the guard, and the reason is on Enrolment.Libraries rather than
        // repeated here - a paraphrase is how the last correction ended up needing two sites.
        //
        // Adding a project under src/ means bumping this number, which is the same
        // deliberate moment the unenrolled count is built around.
        Assert.NotEmpty(stubs);
        Assert.Equal(Enrolment.Libraries, libraries.Length);
        Assert.Contains(nameof(CustodianHeldKeys), shipped);
        Assert.Contains(nameof(AuthSession), shipped);

        Assert.DoesNotContain(stubs, shipped.Contains);
    }

    /// <summary>
    /// Where the compiled copy of a sample lives.
    /// </summary>
    /// <remarks>
    /// Named by the enrolment rather than derived from the member's identifier, which carries brackets,
    /// commas and braces and would make an unreadable file name. ONE file, read from the sources: a copy
    /// emitted to the output beside the compiled one could disagree with it, and this row would then
    /// compare a doc comment against a file no compiler ever read.
    /// </remarks>
    private static string CopyOf(string repositoryRoot, DocSample sample) => Path.Combine(
        repositoryRoot,
        "tests",
        "Abblix.DocSamples",
        "Samples",
        sample.Copy);

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
