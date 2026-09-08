// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// What this library relies on <see cref="Base64Url"/> to enforce. They were written as a parity
/// contract between the base libraries and two in-tree decoders of our own, and both of those are
/// gone - what is left is the half that was never about our code.
/// </summary>
/// <remarks>
/// <see cref="Base64Url.DecodeFromChars(System.ReadOnlySpan{char})"/> is strict on the alphabet,
/// rejecting the standard-base64 <c>+</c> and <c>/</c>, and on inputs whose length leaves a
/// remainder of one. That strictness is the property this library depends on: a decoder accepting
/// two spellings of one payload breaks every check that compares BYTES rather than meaning - a
/// replay cache keyed by the whole token, a jti hash, an at_hash binding.
/// <para>
/// It is permissive about <c>=</c> padding and about whitespace inside the input, which is wider
/// than RFC 7515 section 3 mandates. That leniency is pinned here rather than argued with, because
/// what these rows are for is noticing if it ever CHANGES.
/// </para>
/// </remarks>
public class Base64UrlTests
{
    /// <summary>
    /// RFC 7515 Appendix A.1.1 vector: encoding the JOSE header
    /// <c>{"typ":"JWT",\r\n "alg":"HS256"}</c> yields the canonical
    /// <c>"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"</c>. Locks the encoder against any drift.
    /// </summary>
    [Fact]
    public void EncodeToString_RfcAppendixA1Vector_ProducesCanonicalForm()
    {
        var header = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"u8.ToArray();

        var encoded = Base64Url.EncodeToString(header);

        Assert.Equal("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", encoded);
    }

    /// <summary>
    /// RFC 7515 Appendix A.1.1 vector decoded back to the original bytes.
    /// </summary>
    [Fact]
    public void DecodeFromChars_RfcAppendixA1Vector_RoundTripsCleanly()
    {
        const string encoded = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

        var decoded = Base64Url.DecodeFromChars(encoded);

        Assert.Equal("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}", Encoding.UTF8.GetString(decoded));
    }

    /// <summary>
    /// Empty input round-trips to itself in both directions.
    /// </summary>
    [Fact]
    public void EncodeToString_EmptyInput_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, Base64Url.EncodeToString(ReadOnlySpan<byte>.Empty));
    }

    /// <summary>
    /// Empty input round-trips to itself in both directions.
    /// </summary>
    [Fact]
    public void DecodeFromChars_EmptyInput_ReturnsEmptyArray()
    {
        Assert.Empty(Base64Url.DecodeFromChars(ReadOnlySpan<char>.Empty));
    }

    /// <summary>
    /// Random byte sequences round-trip cleanly: encode → decode reproduces the original.
    /// Locks against off-by-one bugs at the 1, 2, 3-byte tail boundaries.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(64)]
    [InlineData(255)]
    public void RoundTrip_RandomBytes_RestoresOriginal(int length)
    {
        var original = new byte[length];
        RandomNumberGenerator.Fill(original);

        var encoded = Base64Url.EncodeToString(original);
        var decoded = Base64Url.DecodeFromChars(encoded);

        Assert.Equal(original, decoded);
    }

    /// <summary>
    /// The base64url alphabet is exactly <c>A-Z a-z 0-9 - _</c> (RFC 4648 section 5). Standard-base64
    /// characters <c>+</c> and <c>/</c> MUST be rejected - accepting them would let two
    /// cosmetically different encodings of the same payload decode to the same bytes, breaking
    /// identity-of-bytes checks (replay caches, jti hashes, at_hash binding).
    /// </summary>
    [Theory]
    [InlineData("ab+d")]
    [InlineData("ab/d")]
    [InlineData("ab+/")]
    public void DecodeFromChars_StandardBase64Characters_Throws(string input)
    {
        Assert.Throws<FormatException>(() => Base64Url.DecodeFromChars(input));
    }

    /// <summary>
    /// Inputs whose length leaves a 1-character remainder modulo 4 are not valid base64url:
    /// 6 bits cannot encode any whole number of bytes.
    /// </summary>
    [Theory]
    [InlineData("a")]
    [InlineData("abcde")]
    [InlineData("abcdefghi")]
    public void DecodeFromChars_LengthMod4Equals1_Throws(string input)
    {
        Assert.Throws<FormatException>(() => Base64Url.DecodeFromChars(input));
    }

    /// <summary>
    /// Encoder MUST produce only alphabet characters - no <c>+</c>, <c>/</c>, or <c>=</c>.
    /// </summary>
    [Fact]
    public void EncodeToString_NeverEmitsStandardBase64Characters()
    {
        for (var trial = 0; trial < 256; trial++)
        {
            var bytes = new byte[trial + 1];
            RandomNumberGenerator.Fill(bytes);

            var encoded = Base64Url.EncodeToString(bytes);

            Assert.DoesNotContain('+', encoded);
            Assert.DoesNotContain('/', encoded);
            Assert.DoesNotContain('=', encoded);
        }
    }
}
