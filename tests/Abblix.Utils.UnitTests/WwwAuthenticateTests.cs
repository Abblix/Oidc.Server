// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// The <c>WWW-Authenticate</c> grammar, which two packages under two licences now share.
/// </summary>
/// <remarks>
/// The quoting is the part worth pinning. A realm or description carrying a quotation mark or a backslash
/// produces a header that a client parses into something else entirely, and the failure surfaces at the
/// client as a malformed challenge rather than here as a bad string.
/// </remarks>
public class WwwAuthenticateTests
{
    [Fact]
    public void Challenge_SchemeAlone_IsJustTheScheme()
        => Assert.Equal("Bearer", WwwAuthenticate.Challenge("Bearer"));

    /// <summary>
    /// The form RFC 6750 Section 3.1 requires of a request that presented no credentials: the scheme and
    /// the realm, and nothing a caller could mistake for a diagnosis of what it did wrong.
    /// </summary>
    [Fact]
    public void Challenge_WithRealm_CarriesNoErrorAttributes()
    {
        var challenge = WwwAuthenticate.Challenge("Bearer", "https://transmitter.example");

        Assert.Equal("Bearer realm=\"https://transmitter.example\"", challenge);
        Assert.DoesNotContain("error", challenge);
    }

    [Fact]
    public void Challenge_WithError_NamesItAfterTheRealm()
        => Assert.Equal(
            "Bearer realm=\"r\", error=\"invalid_token\", error_description=\"expired\"",
            WwwAuthenticate.Challenge("Bearer", "r", "invalid_token", "expired"));

    /// <summary>
    /// An absent realm leaves the error first rather than emitting an empty parameter, so the delimiter
    /// logic has to notice which parameter is actually first.
    /// </summary>
    [Fact]
    public void Challenge_WithoutRealm_StartsAtTheError()
        => Assert.Equal(
            "Bearer error=\"insufficient_scope\"",
            WwwAuthenticate.Challenge("Bearer", null, "insufficient_scope", null));

    /// <summary>
    /// RFC 9110 Section 5.6.4: inside a quoted-string a quotation mark is backslash-escaped and a
    /// backslash is doubled. Without this a value carrying either one closes the string early and the
    /// rest of the header is read as something else.
    /// </summary>
    [Theory]
    [InlineData("a\"b", "a\\\"b")]
    [InlineData("a\\b", "a\\\\b")]
    [InlineData("\"", "\\\"")]
    [InlineData("back\\slash and \"quote\"", "back\\\\slash and \\\"quote\\\"")]
    public void Challenge_EscapesQuotedStringSpecials(string realm, string expected)
        => Assert.Equal($"Bearer realm=\"{expected}\"", WwwAuthenticate.Challenge("Bearer", realm));

    /// <summary>
    /// An empty value is omitted rather than emitted as <c>name=""</c>, which would be a parameter the
    /// caller has to interpret and cannot.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Challenge_EmptyRealm_IsOmitted(string? realm)
        => Assert.Equal("Bearer", WwwAuthenticate.Challenge("Bearer", realm));

    [Fact]
    public void Challenge_EmptyDescription_LeavesTheErrorAlone()
        => Assert.Equal(
            "Bearer error=\"invalid_token\"",
            WwwAuthenticate.Challenge("Bearer", null, "invalid_token", ""));
    /// <summary>
    /// Only what the quoted-string grammar admits reaches the header value.
    /// </summary>
    /// <remarks>
    /// RFC 9110 Section 5.6.4: <c>qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text</c>, and
    /// <c>quoted-pair</c> carries DQUOTE and the backslash. So HTAB is legal and passes through -
    /// an earlier version of this row asserted it was replaced, which pinned an alteration of a
    /// value the grammar allows.
    /// <para>
    /// What is replaced is everything with no place in the grammar, and CR or LF most of all: either
    /// ends the header field. Measured before this was closed, the builder emitted a raw CRLF while
    /// the comment beside it said such a value was "rejected upstream" - it was not; the only thing
    /// standing there was the HTTP server refusing the header, which is a fault, not a refusal.
    /// </para>
    /// <para>
    /// Values reaching the builder are not always the library's own: an error description can quote
    /// what a client put in a token, and a JSON string carries CR and LF perfectly well.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("bad\r\nX-Injected: 1", "bad  X-Injected: 1")]
    [InlineData("bad\u0000nul", "bad nul")]
    [InlineData("bad\u007fdel", "bad del")]
    [InlineData("keeps\ttab", "keeps\ttab")]
    [InlineData("keeps obs-text é", "keeps obs-text é")]

    // Every END of every emitted range, because a row in the middle of a range says nothing about
    // where it stops: measured, each bound could be moved by one with all 313 rows green, so the
    // builder could go back to replacing a legal character - the defect this theory exists to close,
    // one character along - or start emitting a forbidden one.
    //
    // The printable range's lower end takes TWO rows because its first character is unobservable: SP
    // falling out of the range is replaced BY a space, so the output is identical either way. What is
    // observable is U+0021 on one side and U+001F on the other, and they fail differently - one is a
    // legal character silently replaced, the other a control character silently emitted. U+0080 is in
    // the same position at the obs-text floor, and is also part of the run char.IsControl called
    // control characters, which the previous version replaced.
    [InlineData("keeps tilde ~", "keeps tilde ~")]
    [InlineData("bang ! stays", "bang ! stays")]
    [InlineData("unit\u001fseparator", "unit separator")]
    [InlineData("keeps \u0080 the first obs-text", "keeps \u0080 the first obs-text")]
    public void Challenge_EmitsOnlyWhatTheGrammarAdmits(string value, string expected)
    {
        var header = WwwAuthenticate.Challenge("DPoP", ("error_description", value));

        Assert.Equal($"DPoP error_description=\"{expected}\"", header);
    }
}
