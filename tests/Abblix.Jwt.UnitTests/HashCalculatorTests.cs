// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// <see cref="HashCalculator"/> against the worked examples printed in the specifications themselves.
/// </summary>
/// <remarks>
/// These vectors are the point of the class. The issuing side and the verifying side compute this
/// binding in different packages, and a shared implementation only helps if it is the one the rest of
/// the world computes too - a self-consistent pair would agree with each other and with nobody else.
/// So the expected values here are copied from OpenID Connect Core 1.0, not produced by running the
/// code and recording what it said.
/// </remarks>
public class HashCalculatorTests
{
    /// <summary>
    /// OpenID Connect Core 1.0 section 3.3.2.11 works this one through: an authorization code of
    /// "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk" with an ID Token signed using
    /// RS256 gives a c_hash of "LDktKdoQak3Pk0cnXxCltA".
    /// </summary>
    [Fact]
    public void CodeHash_MatchesTheSpecificationsWorkedExample()
    {
        const string code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";

        Assert.Equal("LDktKdoQak3Pk0cnXxCltA", HashCalculator.Compute(SigningAlgorithms.RS256, code));
    }

    /// <summary>
    /// Section 3.3.2.11 prints the at_hash for the same example: an access token of
    /// "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" under RS256 gives "77QmUPtjPfzWtF2AnpK9RQ".
    /// </summary>
    [Fact]
    public void AccessTokenHash_MatchesTheSpecificationsWorkedExample()
    {
        const string accessToken = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

        Assert.Equal("77QmUPtjPfzWtF2AnpK9RQ", HashCalculator.Compute(SigningAlgorithms.RS256, accessToken));
    }

    /// <summary>
    /// The pairing is by digest size, not by signature family, so every algorithm ending in the same
    /// three digits produces the same value.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, SigningAlgorithms.PS256)]
    [InlineData(SigningAlgorithms.RS256, SigningAlgorithms.ES256)]
    [InlineData(SigningAlgorithms.RS256, SigningAlgorithms.HS256)]
    [InlineData(SigningAlgorithms.RS384, SigningAlgorithms.ES384)]
    [InlineData(SigningAlgorithms.RS512, SigningAlgorithms.ES512)]
    public void AlgorithmsOfTheSameDigestSize_Agree(string first, string second)
    {
        const string value = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

        Assert.Equal(HashCalculator.Compute(first, value), HashCalculator.Compute(second, value));
    }

    /// <summary>
    /// And algorithms of different digest sizes must not, or the size would carry no information.
    /// </summary>
    [Fact]
    public void DifferentDigestSizes_Differ()
    {
        const string value = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

        var sha256 = HashCalculator.Compute(SigningAlgorithms.RS256, value);
        var sha384 = HashCalculator.Compute(SigningAlgorithms.RS384, value);
        var sha512 = HashCalculator.Compute(SigningAlgorithms.RS512, value);

        Assert.Equal(3, new HashSet<string?> { sha256, sha384, sha512 }.Count);
    }

    /// <summary>
    /// The result is the left-most half of the digest, so its length follows the digest: 16 bytes of a
    /// SHA-256, 24 of a SHA-384, 32 of a SHA-512.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, 16)]
    [InlineData(SigningAlgorithms.RS384, 24)]
    [InlineData(SigningAlgorithms.RS512, 32)]
    public void ResultIsTheLeftMostHalfOfTheDigest(string algorithm, int expectedBytes)
    {
        var encoded = HashCalculator.Compute(algorithm, "any-value")!;

        Assert.Equal(expectedBytes, System.Buffers.Text.Base64Url.DecodeFromChars(encoded).Length);
    }

    /// <summary>
    /// It really is the LEFT half, not the right one and not the whole digest.
    /// </summary>
    [Fact]
    public void ResultIsTheLeftHalf_NotTheRight()
    {
        const string value = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(value));

        var expected = System.Buffers.Text.Base64Url.EncodeToString(digest.AsSpan(0, digest.Length / 2));

        Assert.Equal(expected, HashCalculator.Compute(SigningAlgorithms.RS256, value));
    }

    /// <summary>
    /// An algorithm with no digest paired to it yields no value at all, rather than some fallback. The
    /// caller decides what that means: an issuer omits the claim, a client refuses the binding.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.None)]
    [InlineData("EdDSA")]
    [InlineData("")]
    public void AlgorithmWithNoPairedDigest_YieldsNull(string algorithm)
    {
        Assert.Null(HashCalculator.Compute(algorithm, "any-value"));
    }
}
