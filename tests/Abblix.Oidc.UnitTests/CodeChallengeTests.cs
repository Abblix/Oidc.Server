// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Oidc.UnitTests;

public class CodeChallengeTests
{
    /// <summary>
    /// The worked example of RFC 7636 Appendix B.
    /// </summary>
    [Fact]
    public void S256_MatchesTheWorkedExampleOfTheSpecification()
    {
        Assert.Equal(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallenge.Calculate(CodeChallengeMethods.S256, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    /// <summary>
    /// The verifier of RFC 7636 Appendix B under SHA-512, computed outside this library.
    /// </summary>
    [Fact]
    public void S512_IsTheBase64UrlOfTheSha512OfTheVerifier()
    {
        Assert.Equal(
            "gF6OL6GcjNWj0_70FLf0hrPaehhw-bZdlX_UytXqksUpQdbsb34wySChXvpivpSVbgF5a7PLad6hekkGrqW2Nw",
            CodeChallenge.Calculate(CodeChallengeMethods.S512, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    [Fact]
    public void Plain_IsTheVerifierItself()
    {
        Assert.Equal("verifier", CodeChallenge.Calculate(CodeChallengeMethods.Plain, "verifier"));
    }

    [Fact]
    public void AnUnknownMethod_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CodeChallenge.Calculate("S384", "verifier"));
    }

    /// <summary>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 4.1.1 and RFC 7636 sections 4.1 and 4.2: "code-verifier =
    /// 43*128unreserved" and "code-challenge = 43*128unreserved", unreserved being ALPHA / DIGIT / "-" / "." / "_" / "~".
    /// The worked example's verifier and challenge, and an S512 challenge, are well formed.
    /// </summary>
    [Theory]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")]
    [InlineData("gF6OL6GcjNWj0_70FLf0hrPaehhw-bZdlX_UytXqksUpQdbsb34wySChXvpivpSVbgF5a7PLad6hekkGrqW2Nw")]
    [InlineData("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ.-_~0123456789")]
    public void IsWellFormed_AcceptsTheSyntaxOfTheSpecification(string value)
    {
        Assert.True(CodeChallenge.IsWellFormed(value));
    }

    /// <summary>
    /// Shorter than 43 or longer than 128 characters, or carrying a character outside the unreserved set: the padding
    /// and the two characters base64 has and base64url has not, a space, and a letter outside ASCII.
    /// </summary>
    [Theory]
    [InlineData(42, 'a')]
    [InlineData(129, 'a')]
    [InlineData(0, 'a')]
    [InlineData(43, '=')]
    [InlineData(43, '+')]
    [InlineData(43, '/')]
    [InlineData(43, ' ')]
    [InlineData(43, 'é')]
    public void IsWellFormed_RefusesALengthOrACharacterOutsideTheSyntax(int length, char last)
    {
        var value = length == 0 ? string.Empty : new string('a', length - 1) + last;

        Assert.False(CodeChallenge.IsWellFormed(value));
    }

    [Theory]
    [InlineData(43)]
    [InlineData(128)]
    public void IsWellFormed_AcceptsBothBoundsOfTheLength(int length)
    {
        Assert.True(CodeChallenge.IsWellFormed(new string('a', length)));
    }
}
