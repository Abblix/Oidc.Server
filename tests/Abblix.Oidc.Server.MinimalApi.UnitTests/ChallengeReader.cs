// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Text;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// Reads one WWW-Authenticate challenge by the grammar of RFC 9110 section 11.6.1, <c>auth-scheme [ 1*SP auth-param
/// *( OWS "," OWS auth-param ) ]</c>, so a test compares a parameter's value rather than looking for it as text.
/// </summary>
internal static class ChallengeReader
{
    internal sealed record Challenge(string Scheme, IReadOnlyDictionary<string, string> Parameters);

    private const char Backslash = (char)92;

    public static Challenge Parse(string? challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        var space = challenge.IndexOf(' ');
        if (space < 0)
            return new Challenge(challenge, new Dictionary<string, string>());

        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var position = space + 1;
        while (position < challenge.Length)
        {
            while (position < challenge.Length && challenge[position] is ' ' or ',')
                position++;

            var equals = challenge.IndexOf('=', position);
            var name = challenge[position..equals].Trim();
            position = equals + 1;

            var value = challenge[position] == '"'
                ? ReadQuoted(challenge, ref position)
                : ReadToken(challenge, ref position);

            parameters[name] = value;
        }

        return new Challenge(challenge[..space], parameters);
    }

    /// <summary>
    /// A quoted-string, a backslash escaping the character after it (quoted-pair).
    /// </summary>
    private static string ReadQuoted(string challenge, ref int position)
    {
        var value = new StringBuilder();
        position++;
        while (challenge[position] != '"')
        {
            if (challenge[position] == Backslash)
                position++;

            value.Append(challenge[position++]);
        }

        position++;
        return value.ToString();
    }

    /// <summary>
    /// A token, up to the next comma.
    /// </summary>
    private static string ReadToken(string challenge, ref int position)
    {
        var start = position;
        while (position < challenge.Length && challenge[position] != ',')
            position++;

        return challenge[start..position].Trim();
    }
}
