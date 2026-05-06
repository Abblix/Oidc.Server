// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Buffers.Text;
using System.Text;
using Xunit;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Contract tests for <see cref="Base64Url"/>. On net9.0+ exercises the BCL implementation;
/// on net8.0 exercises the in-tree polyfill in <c>Abblix.Utils/Polyfills/Base64Url.cs</c>.
/// The two sides MUST behave identically — these tests are the parity contract.
/// </summary>
/// <remarks>
/// BCL's <see cref="Base64Url.DecodeFromChars"/> is strict on the alphabet (rejects standard-base64
/// <c>+</c> and <c>/</c>) and on length-mod-4-equals-1 inputs, which fixes the main correctness gap
/// in the legacy <c>HttpServerUtility.UrlTokenDecode</c>. The BCL is permissive on <c>=</c> padding
/// and on whitespace inside the input — accepting them as compat tolerance. That residual leniency
/// is wider than RFC 7515 §3 strict mandates, but narrower than the legacy decoder, and is
/// acceptable for the migration's scope. Tests assert what BCL actually enforces.
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
        var random = new Random(length);
        var original = new byte[length];
        random.NextBytes(original);

        var encoded = Base64Url.EncodeToString(original);
        var decoded = Base64Url.DecodeFromChars(encoded);

        Assert.Equal(original, decoded);
    }

    /// <summary>
    /// The base64url alphabet is exactly <c>A-Z a-z 0-9 - _</c> (RFC 4648 §5). Standard-base64
    /// characters <c>+</c> and <c>/</c> MUST be rejected — accepting them would let two
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
    /// Encoder MUST produce only alphabet characters — no <c>+</c>, <c>/</c>, or <c>=</c>.
    /// </summary>
    [Fact]
    public void EncodeToString_NeverEmitsStandardBase64Characters()
    {
        var random = new Random(42);
        for (var trial = 0; trial < 256; trial++)
        {
            var bytes = new byte[trial + 1];
            random.NextBytes(bytes);

            var encoded = Base64Url.EncodeToString(bytes);

            Assert.DoesNotContain('+', encoded);
            Assert.DoesNotContain('/', encoded);
            Assert.DoesNotContain('=', encoded);
        }
    }
}
