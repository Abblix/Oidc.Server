// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Binary;
using System.Buffers.Text;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// A device code carrying the instant it expires, so the server can tell an expired one from one it never issued
/// after the record behind it is gone.
/// </summary>
/// <remarks>
/// <para>
/// The instant is not protected, so a client can write any instant it likes. The answer drawn from it -
/// expired_token when it has passed, invalid_grant otherwise - depends only on what the client sent, so it tells a
/// guesser nothing about what was ever issued. The device code is echoed to the token endpoint and never shown to
/// the user (RFC 8628 sections 3.2 and 3.4).
/// </para>
/// <para>
/// An auth_req_id does not carry one: CIBA Core section 11 requires invalid_grant for an auth_req_id that is
/// invalid, and one written by the client with a past instant is exactly that.
/// </para>
/// </remarks>
internal static class ExpiringIdentifier
{
    /// <summary>
    /// Between the random part and the instant; it is not in the base64url alphabet, so the split is unambiguous.
    /// </summary>
    private const char Separator = '.';

    /// <summary>
    /// <paramref name="randomPart"/> followed by <paramref name="expiresAt"/>.
    /// </summary>
    public static string Compose(string randomPart, DateTimeOffset expiresAt)
    {
        Span<byte> instant = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(instant, expiresAt.ToUnixTimeSeconds());
        return randomPart + Separator + Base64Url.EncodeToString(instant);
    }

    /// <summary>
    /// Whether <paramref name="identifier"/> carries an instant that has come by <paramref name="now"/>; one
    /// carrying none has not expired, as far as it can say.
    /// </summary>
    /// <remarks>
    /// The instant itself counts as expired, the boundary the stored records are held to as well, so a poll at
    /// the expiry gets the same answer whether the record is still there or already evicted.
    /// </remarks>
    public static bool HasExpired(string identifier, DateTimeOffset now)
        => TryReadExpiry(identifier, out var expiresAt) && expiresAt <= now;

    /// <summary>
    /// The instant <paramref name="identifier"/> expires, when it carries one.
    /// </summary>
    public static bool TryReadExpiry(string identifier, out DateTimeOffset expiresAt)
    {
        expiresAt = default;

        var separator = identifier.LastIndexOf(Separator);
        if (separator < 0)
            return false;

        // TryDecodeFromChars throws rather than refuses on a character outside the alphabet
        var encoded = identifier.AsSpan(separator + 1);
        if (!Base64Url.IsValid(encoded, out var decodedLength) || decodedLength != sizeof(long))
            return false;

        Span<byte> instant = stackalloc byte[sizeof(long)];
        Base64Url.DecodeFromChars(encoded, instant);
        expiresAt = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64BigEndian(instant));
        return true;
    }
}
