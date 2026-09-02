// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Xml.Linq;
using System.Text.RegularExpressions;

namespace Abblix.DocSamples;

/// <summary>
/// One enrolled code sample: where it lives in the sources, and which of that file's blocks it is.
/// </summary>
/// <param name="Source">The source file, relative to the repository root.</param>
/// <param name="Index">Which <c>&lt;code&gt;</c> block of that file, counting from zero.</param>
public sealed record DocSample(string Source, int Index)
{
    public override string ToString() => $"{Source}#{Index}";
}

/// <summary>
/// Reads the <c>&lt;code&gt;</c> blocks out of a source file's doc comments.
/// </summary>
/// <remarks>
/// A doc-comment sample is compiled by nothing, so it rots silently on every rename: the one documenting
/// CIBA completion shipped eight defects at once, six of them names appearing nowhere else in the
/// repository. The gate is to put the sample's text into a project that references the library and let
/// the compiler answer - no false positive is possible, since a sample either compiles or it does not.
/// <para>
/// What this class does is only the reading. The compiled copy lives beside it as ordinary source, and
/// <c>DocSampleTests</c> is what refuses the two to drift: the copy is what the compiler checks, and a
/// doc comment edited without regenerating the copy would otherwise leave the gate guarding yesterday's
/// text.
/// </para>
/// </remarks>
public static partial class DocSampleReader
{
    /// <summary>
    /// The lines of one enrolled sample, with the comment prefix and the XML escaping removed.
    /// </summary>
    /// <exception cref="InvalidOperationException">The file has no block at that index - which means the
    /// enrolment names a sample that has been moved or deleted, and the gate is guarding nothing.
    /// </exception>
    public static IReadOnlyList<string> Read(string repositoryRoot, DocSample sample)
    {
        var blocks = BlocksIn(File.ReadAllLines(Path.Combine(repositoryRoot, sample.Source)));
        if (sample.Index >= blocks.Count)
        {
            throw new InvalidOperationException(
                $"{sample} does not exist: the file carries {blocks.Count} code block(s). A sample that "
                + "moved takes its enrolment with it, or the gate compiles text nothing documents.");
        }

        return blocks[sample.Index];
    }

    /// <summary>
    /// Every code block in a source file, in the order they appear.
    /// </summary>
    /// <remarks>
    /// Read with an XML parser rather than by looking for the tag's text, because the tag has more forms
    /// than a reader remembers: <c>&lt;code&gt;</c> opened and closed on ONE line, and
    /// <c>&lt;code language="csharp"&gt;</c> with an attribute, are both ordinary C# and were both
    /// invisible to a scan that tested for the literal string and treated each marker as owning its
    /// line. A sample written either way could be added to the library without moving the uncompiled
    /// count, which is the one thing that count exists to prevent.
    /// <para>
    /// Counted rather than matched by content, so an enrolment cannot silently follow the wrong block
    /// when one is added above it - the count moves, the index names a different sample, and the drift
    /// test says so rather than comparing something else quietly.
    /// </para>
    /// <para>
    /// A run of doc-comment lines is one fragment and is wrapped in a root element before parsing, since
    /// a doc comment has several top-level tags and no root of its own. A fragment that will not parse
    /// is not silently skipped - the compiler already refuses it, because this repository builds the
    /// documentation file with warnings as errors, so reaching a malformed one here means the parser and
    /// the compiler disagree and that is worth the exception.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<IReadOnlyList<string>> BlocksIn(IReadOnlyList<string> sourceLines)
    {
        var blocks = new List<IReadOnlyList<string>>();

        foreach (var fragment in DocCommentFragments(sourceLines))
        {
            var root = XElement.Parse($"<doc>{fragment}</doc>", LoadOptions.PreserveWhitespace);

            foreach (var code in root.Descendants("code"))
            {
                blocks.Add(code.Value
                    .ReplaceLineEndings("\n")
                    .Split('\n')
                    .Select(line => line.TrimEnd())
                    .SkipWhile(string.IsNullOrWhiteSpace)
                    .Reverse()
                    .SkipWhile(string.IsNullOrWhiteSpace)
                    .Reverse()
                    .ToArray());
            }
        }

        return blocks;
    }

    /// <summary>
    /// Each unbroken run of doc-comment lines, joined back into one piece of XML.
    /// </summary>
    /// <remarks>
    /// Per RUN rather than per file, so a tag left open in one member's comment cannot swallow the next
    /// member's - which is the failure mode of treating the whole file as one document.
    /// </remarks>
    private static IEnumerable<string> DocCommentFragments(IReadOnlyList<string> sourceLines)
    {
        var current = new List<string>();

        foreach (var line in sourceLines)
        {
            var text = Uncomment(line);
            if (text is null)
            {
                if (current.Count > 0)
                    yield return string.Join(Environment.NewLine, current);

                current.Clear();
                continue;
            }

            current.Add(text);
        }

        if (current.Count > 0)
            yield return string.Join(Environment.NewLine, current);
    }

    /// <summary>
    /// The text of a doc-comment line, or null when the line is not one.
    /// </summary>
    private static string? Uncomment(string line)
    {
        var match = DocCommentLine().Match(line);
        return match.Success ? match.Groups["text"].Value : null;
    }

    [GeneratedRegex(@"^\s*///\s?(?<text>.*?)\s*$")]
    private static partial Regex DocCommentLine();
}
