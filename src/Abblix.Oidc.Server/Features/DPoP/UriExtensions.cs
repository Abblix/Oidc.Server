// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// URI helpers scoped to the DPoP feature. Kept <c>internal</c> so the extension
/// surface is not advertised to consumers of the library outside this assembly: the
/// normalisation rules baked in are specific to RFC 9449 <c>htu</c> comparison and
/// would be misleading if applied generically.
/// </summary>
internal static class UriExtensions
{
    /// <summary>
    /// Returns the canonical-string form of <paramref name="uri"/> for DPoP <c>htu</c>
    /// comparison per RFC 9449 section 6 and RFC 3986 section 6.2: scheme and host folded to
    /// lowercase, default ports stripped, query and fragment dropped, path preserved
    /// verbatim. Internationalised host names are returned in Punycode ASCII so two
    /// peers produce byte-stable output for the same conceptual URI.
    /// </summary>
    /// <param name="uri">The URI to normalise.</param>
    /// <returns>The canonical-string form suitable for byte-stable equality
    /// comparison with another <c>htu</c> value.</returns>
    internal static string Normalize(this Uri uri)
        => UppercasePercentTriplets(uri.GetLeftPart(UriPartial.Path));

    // RFC 3986 section 6.2.2.2: percent-encoded triplets carry significant case in their two
    // hex digits and MUST be normalised to uppercase. The .NET Uri class folds scheme
    // and host case but leaves percent-triplets verbatim, so we close the gap here.
    private static string UppercasePercentTriplets(string source)
    {
        var firstPercent = source.IndexOf('%');
        if (firstPercent < 0)
            return source;

        var sb = new StringBuilder(source.Length);
        sb.Append(source, 0, firstPercent);
        var i = firstPercent;
        while (i < source.Length)
        {
            if (source[i] == '%' && i + 2 < source.Length)
            {
                sb.Append('%');
                sb.Append(char.ToUpperInvariant(source[i + 1]));
                sb.Append(char.ToUpperInvariant(source[i + 2]));
                i += 3;
            }
            else
            {
                sb.Append(source[i]);
                i++;
            }
        }
        return sb.ToString();
    }
}
