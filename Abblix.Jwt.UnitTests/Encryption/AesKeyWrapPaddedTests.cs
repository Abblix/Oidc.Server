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

using System;
using System.Security.Cryptography;
using Abblix.Jwt.Encryption;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// Known-answer tests for AES Key Wrap with Padding (RFC 5649). The two RFC 5649 §4 vectors pin the multi-block and
/// the single-block wrapping paths of the <see cref="Rfc5649KeyWrap"/> transcription byte-exact, and a cross-check
/// proves the transcription and the platform implementation (used on .NET 10 via <see cref="AesKeyWrapPadded"/>)
/// agree, so a value wrapped on one target framework opens on another.
/// </summary>
public class AesKeyWrapPaddedTests
{
    // RFC 5649 §4: the AES-192 key encryption key shared by both example vectors.
    private static readonly byte[] Rfc5649Kek =
        Convert.FromHexString("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");

    [Theory]
    // RFC 5649 §4.1: 20 octets of key data - more than one semiblock, so the RFC 3394 rounds run.
    [InlineData(
        "c37b7e6492584340bed1220780894115 5068f738",
        "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")]
    // RFC 5649 §4.2: 7 octets - a single padded semiblock, so the single-block AES-ECB path runs.
    [InlineData(
        "466f7250617369",
        "afbeb0f07dfbf5419200f2ccb50bb24f")]
    public void Rfc5649KeyWrap_MatchesRfc5649Vector(string plaintextHex, string expectedWrappedHex)
    {
        var plaintext = Convert.FromHexString(plaintextHex.Replace(" ", ""));
        var expectedWrapped = Convert.FromHexString(expectedWrappedHex);

        var wrapped = Rfc5649KeyWrap.Wrap(Rfc5649Kek, plaintext);
        Assert.Equal(expectedWrapped, wrapped);

        Assert.True(Rfc5649KeyWrap.TryUnwrap(Rfc5649Kek, wrapped, out var recovered));
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Rfc5649KeyWrap_TamperedValue_FailsToUnwrap()
    {
        var wrapped = Rfc5649KeyWrap.Wrap(Rfc5649Kek, Convert.FromHexString("466f7250617369"));
        wrapped[0] ^= 0x01;

        Assert.False(Rfc5649KeyWrap.TryUnwrap(Rfc5649Kek, wrapped, out var recovered));
        Assert.Null(recovered);
    }

    [Fact]
    public void Rfc5649KeyWrap_WrongKey_FailsToUnwrap()
    {
        var wrapped = Rfc5649KeyWrap.Wrap(Rfc5649Kek, Convert.FromHexString("466f7250617369"));
        var wrongKek = Convert.FromHexString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

        Assert.False(Rfc5649KeyWrap.TryUnwrap(wrongKek, wrapped, out var recovered));
        Assert.Null(recovered);
    }

    /// <summary>
    /// The transcription and the dispatcher (which is the native platform implementation on .NET 10) wrap to the
    /// same bytes across the padding boundaries - lengths that fall inside a semiblock, exactly on it, and spanning
    /// several - proving the two implementations of RFC 5649 are interchangeable.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(16)]
    [InlineData(20)]
    [InlineData(31)]
    [InlineData(64)]
    public void Rfc5649KeyWrap_AgreesWithDispatcher(int plaintextLength)
    {
        var kek = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var plaintext = new byte[plaintextLength];
        for (var i = 0; i < plaintextLength; i++)
            plaintext[i] = (byte)(i * 7 + 1);

        var transcribed = Rfc5649KeyWrap.Wrap(kek, plaintext);
        var dispatched = AesKeyWrapPadded.Wrap(kek, plaintext);

        Assert.Equal(dispatched, transcribed);

        Assert.True(AesKeyWrapPadded.TryUnwrap(kek, transcribed, out var recovered));
        Assert.Equal(plaintext, recovered);
    }
}
