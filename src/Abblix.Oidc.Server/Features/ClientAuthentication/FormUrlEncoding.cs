// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Reverses the application/x-www-form-urlencoded encoding RFC 6749 section 2.3.1 applies to the client identifier
/// and the client password of the HTTP Basic scheme, strictly.
/// </summary>
/// <remarks>
/// RFC 6749 Appendix B: the values "resulting from reversing the name/value encoding consequently need to be treated as
/// octet sequences, to be decoded using the UTF-8 character encoding scheme". A plus sign is a space, a percent sign
/// begins the two hexadecimal digits of one octet, and any other character stands for its own UTF-8 octets. A percent
/// sign without two digits, or octets that are not UTF-8, decode to nothing rather than to a guess, as the lenient
/// decoders of the platform would, so a malformed credential matches no client.
/// </remarks>
internal static class FormUrlEncoding
{
    private const int HexDigitsPerOctet = 2;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Decodes <paramref name="encoded"/>, answering false when it is malformed.
    /// </summary>
    /// <param name="encoded">The encoded value.</param>
    /// <param name="decoded">The value it encodes.</param>
    public static bool TryDecode(string encoded, [NotNullWhen(true)] out string? decoded)
    {
        decoded = null;
        var octets = new List<byte>(encoded.Length);
        Span<byte> buffer = stackalloc byte[4];

        var i = 0;
        while (i < encoded.Length)
        {
            switch (encoded[i])
            {
                case '+':
                    octets.Add((byte)' ');
                    i++;
                    break;

                case '%':
                    if (i + HexDigitsPerOctet >= encoded.Length ||
                        !byte.TryParse(
                            encoded.AsSpan(i + 1, HexDigitsPerOctet),
                            NumberStyles.AllowHexSpecifier,
                            CultureInfo.InvariantCulture,
                            out var octet))
                    {
                        return false;
                    }

                    octets.Add(octet);
                    i += 1 + HexDigitsPerOctet;
                    break;

                default:
                    // The credentials were decoded from UTF-8 with replacement, so no lone surrogate reaches here
                    var rune = Rune.GetRuneAt(encoded, i);
                    var length = rune.EncodeToUtf8(buffer);
                    octets.AddRange(buffer[..length]);
                    i += rune.Utf16SequenceLength;
                    break;
            }
        }

        try
        {
            decoded = StrictUtf8.GetString([..octets]);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
