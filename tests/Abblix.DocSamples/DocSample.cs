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
/// questions by the time these files exist - they contain doc comments and nothing else - so the count
/// they give is a fact about the samples rather than about a parser. It differs: 18 blocks against the
/// 16 the last parser found.
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
    /// How many code blocks the compiler recorded across every documented library.
    /// </summary>
    public static int BlockCount()
        => Documents().Sum(document => document.Descendants("code").Count());

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
