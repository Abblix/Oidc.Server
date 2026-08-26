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

            // RFC 9110 Section 5.6.4: inside a quoted-string each `"` must be backslash-escaped and `\`
            // itself doubled. Anything else - control bytes, CR and LF - is rejected upstream rather than
            // mangled here, because silently mutating a value hides where the malformed input came from.
            foreach (var c in value)
            {
                if (c is '"' or '\\')
                    builder.Append('\\');

                builder.Append(c);
            }

            builder.Append('"');
            first = false;
        }
    }
}
