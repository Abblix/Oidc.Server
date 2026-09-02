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
    /// A control character never reaches the header value.
    /// </summary>
    /// <remarks>
    /// The quoted-string grammar has no escape for one, and a CR or an LF ends the header field - so a
    /// value carrying either would split the response, or be refused by the server writing it, which is
    /// a fault rather than a refusal. Measured before this was closed: the builder emitted a raw CRLF,
    /// and the comment beside it said such a value was "rejected upstream".
    /// <para>
    /// Values reaching the builder are not always the library's own. An error description can quote
    /// what a client put in a token, and a JSON string carries CR and LF perfectly well.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("bad\r\nX-Injected: 1")]
    [InlineData("bad\u0000nul")]
    [InlineData("bad\ttab")]
    public void Challenge_WithAControlCharacterInAValue_EmitsNone(string value)
    {
        var header = WwwAuthenticate.Challenge("DPoP", ("error_description", value));

        // The control: the surrounding text really did arrive, so an empty header would not pass this.
        Assert.Contains("bad", header, StringComparison.Ordinal);

        Assert.DoesNotContain(header, char.IsControl);
    }
}
