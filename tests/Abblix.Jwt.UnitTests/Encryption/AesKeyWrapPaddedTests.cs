// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Abblix.Jwt.Encryption;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// Known-answer tests for AES Key Wrap with Padding, against the two vectors RFC 5649 section 4
/// publishes.
/// </summary>
/// <remarks>
/// The vectors belong to the specification rather than to any implementation of it, which is why they
/// outlived the transcription they were first written against. What they hold is that a value this
/// library wraps is the value the standard says it should be - and therefore that a key ring written
/// by an older version of this library, or by anything else implementing the same standard, still
/// opens here.
/// <para>
/// The two are chosen for different paths through the algorithm: twenty octets is more than one
/// semiblock and runs the RFC 3394 rounds, seven octets is a single padded semiblock and does not.
/// </para>
/// </remarks>
public class AesKeyWrapPaddedTests
{
    // RFC 5649 section 4: the AES-192 key encryption key shared by both example vectors.
    private static readonly byte[] Rfc5649Kek =
        Convert.FromHexString("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");

    private static byte[] Wrap(byte[] keyEncryptionKey, byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;
        return aes.EncryptKeyWrapPadded(plaintext);
    }

    private static bool TryUnwrap(byte[] keyEncryptionKey, byte[] wrapped, out byte[]? plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = keyEncryptionKey;
        return aes.TryUnwrapKeyPadded(wrapped, out plaintext);
    }

    [Theory]
    // RFC 5649 section 4.1: 20 octets of key data - more than one semiblock, so the RFC 3394 rounds run.
    [InlineData(
        "c37b7e6492584340bed1220780894115 5068f738",
        "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")]
    // RFC 5649 section 4.2: 7 octets - a single padded semiblock, so the single-block AES-ECB path runs.
    [InlineData(
        "466f7250617369",
        "afbeb0f07dfbf5419200f2ccb50bb24f")]
    public void MatchesRfc5649Vector(string plaintextHex, string expectedWrappedHex)
    {
        var plaintext = Convert.FromHexString(plaintextHex.Replace(" ", ""));
        var expectedWrapped = Convert.FromHexString(expectedWrappedHex);

        var wrapped = Wrap(Rfc5649Kek, plaintext);
        Assert.Equal(expectedWrapped, wrapped);

        Assert.True(TryUnwrap(Rfc5649Kek, wrapped, out var recovered));
        Assert.Equal(plaintext, recovered);
    }

    /// <summary>
    /// A wrapped value carries its own integrity check, so a changed byte does not decrypt to
    /// something plausible - it is refused.
    /// </summary>
    [Fact]
    public void TamperedValue_FailsToUnwrap()
    {
        var wrapped = Wrap(Rfc5649Kek, Convert.FromHexString("466f7250617369"));
        wrapped[0] ^= 0xff;

        Assert.False(TryUnwrap(Rfc5649Kek, wrapped, out var recovered));
        Assert.Null(recovered);
    }

    /// <summary>
    /// And the same for the right value under the wrong key, which is what a key ring entry looks like
    /// after a rotation the reader does not know about.
    /// </summary>
    [Fact]
    public void WrongKey_FailsToUnwrap()
    {
        var wrapped = Wrap(Rfc5649Kek, Convert.FromHexString("466f7250617369"));
        var wrongKeyEncryptionKey =
            Convert.FromHexString("000102030405060708090a0b0c0d0e0f1011121314151617");

        Assert.False(TryUnwrap(wrongKeyEncryptionKey, wrapped, out var recovered));
        Assert.Null(recovered);
    }

    /// <summary>
    /// A value of a length no padded wrap can have is refused rather than thrown on: such values arrive from outside,
    /// a client's pairwise pseudonym among them.
    /// </summary>
    [Theory]
    [InlineData(0)]  // empty
    [InlineData(8)]  // one semiblock - a padded wrap is at least two
    [InlineData(17)] // not a multiple of 8
    [InlineData(23)] // not a multiple of 8
    public void InvalidLength_FailsToUnwrap(int length)
    {
        Assert.False(TryUnwrap(Rfc5649Kek, new byte[length], out var recovered));
        Assert.Null(recovered);
    }
}
