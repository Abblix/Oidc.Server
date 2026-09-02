// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;

namespace Abblix.Utils;

/// <summary>
/// Builds <c>WWW-Authenticate</c> challenge values: the HTTP grammar, not any one protocol's
/// vocabulary of errors.
/// </summary>
/// <remarks>
/// Two packages emit these headers for two different error vocabularies - an authorization server
/// answering with OpenID Connect errors, and a Shared Signals transmitter answering with the three
/// RFC 6750 codes - and they cannot share a type that names either. What they do share is the quoted-string
/// grammar and the rule about when a challenge stays bare, which is what lives here.
/// </remarks>
public static class WwwAuthenticate
{
    /// <summary>
    /// A challenge advertising <paramref name="scheme"/> and nothing else beyond the realm.
    /// </summary>
    /// <remarks>
    /// This is the form RFC 6750 Section 3.1 requires when the request carried no credentials at all:
    /// "If the request lacks any authentication information (e.g., the client was unaware that
    /// authentication is necessary or attempted using an unsupported authentication method), the resource
    /// server SHOULD NOT include an error code or other error information." A caller that has not tried
    /// yet has nothing to correct, and naming an error would describe a failure that did not happen.
    /// </remarks>
    public static string Challenge(string scheme, string? realm = null)
        => Challenge(scheme, ("realm", realm));

    /// <summary>
    /// A challenge naming why the credentials that WERE presented did not suffice.
    /// </summary>
    /// <param name="scheme">The authentication scheme, such as <c>Bearer</c>.</param>
    /// <param name="realm">The protection space, omitted when null or empty.</param>
    /// <param name="error">The error code, from whatever vocabulary the scheme defines.</param>
    /// <param name="errorDescription">Human-readable detail, omitted when null or empty.</param>
    public static string Challenge(string scheme, string? realm, string error, string? errorDescription)
        => Challenge(scheme, ("realm", realm), ("error", error), ("error_description", errorDescription));

    /// <summary>
    /// A challenge carrying whatever parameters the scheme defines, in the order given.
    /// </summary>
    /// <remarks>
    /// Every scheme-specific parameter goes through here rather than being appended to the result, so
    /// that one place decides the delimiter and the escaping. Appending by hand loses both: the first
    /// parameter follows the scheme with a SPACE and the rest with a comma - RFC 9449 Section 7.1 Figure
    /// 15 prints <c>DPoP algs="ES256 PS256"</c>, a challenge whose only parameter is its own - and a
    /// value carrying a quotation mark has to be escaped or it ends the string early.
    /// </remarks>
    public static string Challenge(string scheme, params (string Name, string? Value)[] parameters)
    {
        var builder = new StringBuilder(scheme);
        var first = true;

        foreach (var (name, value) in parameters)
            Append(name, value);

        return builder.ToString();

        void Append(string name, string? value)
        {
            if (string.IsNullOrEmpty(value))
                return;

            builder.Append(first ? " " : ", ").Append(name).Append("=\"");

            // RFC 9110 Section 5.6.4 gives the grammar this writes into:
            //
            //   qdtext      = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
            //   quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
            //
            // So a character is emitted as it stands when it is qdtext, and behind a backslash when it
            // is DQUOTE or the backslash itself - the two the section says a sender SHOULD quote. HTAB
            // is qdtext and needs neither: an earlier version of this replaced every control character
            // and altered a legal value, with a row pinning that as correct.
            //
            // Anything else is replaced rather than emitted, because it has no place in the grammar and
            // CR or LF would end the header field outright. The comment here used to say such a value
            // was "rejected upstream"; measured, it was not - this method emitted a raw CRLF, and the
            // only thing between that and a split response was the HTTP server refusing the header,
            // which is a fault rather than a refusal. Values reaching here are not always ours: an
            // error description can quote what a client put in a token.
            foreach (var c in value)
            {
                if (c is '"' or '\\')
                {
                    builder.Append('\\').Append(c);
                }
                else if (c is '\t' or >= ' ' and <= '~' or >= '\u0080')
                {
                    builder.Append(c);
                }
                else
                {
                    builder.Append(' ');
                }
            }

            builder.Append('"');
            first = false;
        }
    }
}
