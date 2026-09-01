// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
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
    /// Counted rather than matched by content, so an enrolment cannot silently follow the wrong block
    /// when one is added above it - the count moves, the index names a different sample, and the drift
    /// test says so rather than comparing something else quietly.
    /// </remarks>
    public static IReadOnlyList<IReadOnlyList<string>> BlocksIn(IReadOnlyList<string> sourceLines)
    {
        var blocks = new List<IReadOnlyList<string>>();
        List<string>? current = null;

        foreach (var line in sourceLines)
        {
            var text = Uncomment(line);
            if (text is null)
                continue;

            if (text.Contains("<code>", StringComparison.Ordinal))
            {
                current = [];
                continue;
            }

            if (text.Contains("</code>", StringComparison.Ordinal))
            {
                if (current is not null)
                    blocks.Add(current);

                current = null;
                continue;
            }

            // CDATA is how a sample carrying generics avoids escaping every angle bracket; the markers
            // are the comment's, never the sample's.
            current?.Add(WebUtility.HtmlDecode(text.Replace("<![CDATA[", "").Replace("]]>", "")));
        }

        return blocks;
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
