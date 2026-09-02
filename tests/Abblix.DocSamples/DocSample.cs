// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using System.Xml.Linq;

namespace Abblix.DocSamples;

/// <summary>
/// One enrolled code sample: the member it documents, and which of that member's blocks it is.
/// </summary>
/// <param name="Member">The documentation identifier, as the compiler writes it - <c>M:</c> for a
/// method, <c>T:</c> for a type, <c>P:</c> for a property, followed by the fully qualified name.</param>
/// <param name="Index">Which <c>&lt;code&gt;</c> block of that member, counting from zero.</param>
/// <param name="Copy">The file under <c>Samples/</c> that carries this sample as compiled source.</param>
/// <remarks>
/// Keyed by the MEMBER rather than by a file and a line range, because that is the key the compiler
/// itself uses - and because renaming or resignaturing the member changes it, which is exactly when an
/// enrolment should stop matching rather than quietly follow whatever now sits at that position.
/// </remarks>
public sealed record DocSample(string Member, int Index, string Copy)
{
    public override string ToString() => $"{Member}#{Index}";
}

/// <summary>
/// Reads the <c>&lt;code&gt;</c> blocks the COMPILER recorded from the doc comments.
/// </summary>
/// <remarks>
/// A doc-comment sample is compiled by nothing, so it rots silently on every rename: the one documenting
/// CIBA completion shipped eight defects at once, six of them names appearing nowhere else in the
/// repository. The gate is to put the sample's text into a project that references the library and let
/// the compiler answer - no false positive is possible, since a sample either compiles or it does not.
/// <para>
/// The samples are read from the XML documentation files the build already produces, not from the
/// sources. Two hand-written parsers came before this and each was wrong in a way that made the gate
/// look bigger than it was: the first could not see a one-line <c>&lt;code&gt;...&lt;/code&gt;</c> or a
/// tag carrying an attribute, and the second parsed every run of <c>///</c> lines including those inside
/// a block comment, which compiles silently and threw here. The compiler has already answered both
/// questions by the time these files exist - they contain doc comments and nothing else - so what they
/// record is a fact about the samples rather than about a parser.
/// </para>
/// <para>
/// It does NOT follow that every difference from a parser's count is the parser's fault. The raw tag
/// count here is 18 against the sources' 16, and that gap is this reader's - see
/// <see cref="BlockCount"/> - not the old parser's. Two true observations about the parsers carried a
/// third that was never measured.
/// </para>
/// </remarks>
public static class DocSampleReader
{
    /// <summary>
    /// Where the documentation files sit: beside the test assembly, one per referenced library.
    /// </summary>
    /// <remarks>
    /// This project references every library in <c>src/</c> so that every one's documentation lands
    /// here. Referencing only what the samples need would silently narrow the count to those libraries -
    /// <c>Abblix.Oidc.Server.Mvc</c> alone carries six blocks and would have been invisible.
    /// </remarks>
    public static IReadOnlyList<XDocument> Documents()
    {
        var beside = Path.GetDirectoryName(typeof(DocSampleReader).Assembly.Location)!;

        return Directory
            .EnumerateFiles(beside, "Abblix.*.xml")
            .Where(path => Path.GetFileNameWithoutExtension(path) != "Abblix.DocSamples")
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(XDocument.Load)
            .ToArray();
    }

    /// <summary>
    /// The projects this one references by name, as MSBuild wrote them into this assembly.
    /// </summary>
    /// <remarks>
    /// Needed at all because a reference REMOVED from the project file still arrives when another
    /// referenced project pulls it in - measured, dropping <c>Abblix.Utils</c> left its assembly, its
    /// documentation and every row exactly as before. So the reference list and the output are two
    /// different things and have to be compared rather than conflated, and the list cannot be recovered
    /// from the directory the build produces.
    /// <para>
    /// From an assembly attribute rather than from a copy of the csproj, because taking the file name
    /// out of an <c>Include</c> path means deciding what a separator is: the first attempt used
    /// <c>Path.GetFileNameWithoutExtension</c> on a path written with backslashes, which on Linux
    /// is not a separator at all, so the whole path came back as the name. Green here, red on the Ubuntu
    /// runner CI uses - the platform difference is invisible on the machine the code was written on.
    /// MSBuild already knows the answer and its <c>%(Filename)</c> is right by construction.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> ReferencedProjects()
        => typeof(DocSampleReader).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(metadata => metadata.Key == "ReferencedProjects")
            .SelectMany(metadata => (metadata.Value ?? string.Empty).Split(
                ';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

    /// <summary>
    /// The lines of one enrolled sample.
    /// </summary>
    /// <exception cref="InvalidOperationException">The member is not documented, or has no block at that
    /// index - which means the enrolment names a sample that has been renamed, moved or deleted, and the
    /// gate is guarding nothing.</exception>
    public static IReadOnlyList<string> Read(DocSample sample)
    {
        var blocks = Documents()
            .SelectMany(document => document.Descendants("member"))
            .Where(member => (string?)member.Attribute("name") == sample.Member)
            .SelectMany(member => member.Descendants("code"))
            .ToArray();

        if (sample.Index >= blocks.Length)
        {
            throw new InvalidOperationException(
                $"{sample} does not exist: that member carries {blocks.Length} code block(s). A sample "
                + "that moved takes its enrolment with it, or the gate compiles text nothing documents.");
        }

        return Lines(blocks[sample.Index]);
    }

    /// <summary>
    /// How many DISTINCT code samples the compiler recorded across every documented library.
    /// </summary>
    /// <remarks>
    /// Not the raw tag count, because Roslyn copies a primary-constructor type's whole doc comment onto
    /// both <c>T:</c> and <c>M:...#ctor</c>, so one sample on such a type is recorded twice. Counting
    /// tags made the total 18 where the sources hold 16, and reading that gap as a parser defect pointed
    /// at the wrong site entirely: the earlier parser's 16 was right about this, and the duplication is
    /// the reader's.
    /// <para>
    /// A constructor's blocks are dropped only when its WHOLE documented body is identical to its
    /// declaring type's, not merely its code text. The copy Roslyn makes is byte-for-byte, so the whole
    /// body still catches it, unless the author copied the WHOLE comment too, which nothing in the XML can
    /// tell from Roslyn's own copy. Matching on the code alone also collapsed an EXPLICIT constructor whose
    /// author deliberately repeats the type's sample - measured, a real sample lost and the uncompiled
    /// remainder unmoved, which is precisely the silence this gate exists to break.
    /// </para>
    /// </remarks>
    public static int BlockCount()
    {
        var blocks = Documents()
            .SelectMany(document => document.Descendants("member"))
            .Select(member => (
                Name: (string?)member.Attribute("name") ?? string.Empty,
                Body: BodyOf(member),
                Count: member.Descendants("code").Count()))
            .Where(member => member.Count > 0)
            .ToArray();

        var byName = blocks.ToLookup(member => member.Name);

        return blocks
            .Where(member => !IsCopyOfItsType(member.Name, member.Body, byName))
            .Sum(member => member.Count);
    }

    /// <summary>
    /// A documented member's body, with the name it is filed under removed so two members can be
    /// compared for carrying the same documentation.
    /// </summary>
    private static string BodyOf(XElement member)
    {
        var copy = new XElement(member);
        copy.Attribute("name")?.Remove();
        return copy.ToString(SaveOptions.None);
    }

    /// <summary>
    /// Whether this member is a constructor carrying its declaring type's documentation verbatim, which
    /// is what Roslyn writes for a primary constructor.
    /// </summary>
    private static bool IsCopyOfItsType(
        string name, string body, ILookup<string, (string Name, string Body, int Count)> byName)
    {
        const string ConstructorMarker = ".#ctor";

        if (!name.StartsWith("M:", StringComparison.Ordinal))
            return false;

        var marker = name.IndexOf(ConstructorMarker, StringComparison.Ordinal);
        if (marker < 0)
            return false;

        var declaringType = "T:" + name[2..marker];

        return byName[declaringType].Any(type => string.Equals(type.Body, body, StringComparison.Ordinal));
    }

    /// <summary>
    /// A block's text as lines, with the leading and trailing blank ones dropped.
    /// </summary>
    /// <remarks>
    /// The compiler keeps the comment's own indentation, and the block's first and last lines are the
    /// newlines either side of the tag rather than sample text.
    /// </remarks>
    private static IReadOnlyList<string> Lines(XElement code)
        => code.Value
            .ReplaceLineEndings("\n")
            .Split('\n')
            .SkipWhile(string.IsNullOrWhiteSpace)
            .Reverse()
            .SkipWhile(string.IsNullOrWhiteSpace)
            .Reverse()
            .ToArray();
}
