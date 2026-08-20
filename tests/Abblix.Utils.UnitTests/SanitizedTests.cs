// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils.UnitTests;

using Xunit;

/// <summary>
/// Contains unit tests for the <see cref="Sanitized"/> struct to ensure it correctly sanitizes input strings.
/// </summary>
public class SanitizedTests
{
    /// <summary>
    /// Tests that the original string is returned when no special characters are present.
    /// </summary>
    [Fact]
    public void ToString_ShouldReturnOriginalString_WhenNoSpecialCharacters()
    {
        const string input = "HelloWorld";
        Sanitized sanitizedValue = input;
        Assert.Equal(input, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that control characters are removed from the string.
    /// </summary>
    [Fact]
    public void ToString_ShouldRemoveControlCharacters()
    {
        const string input = "Hello\x01\x02\x03World";
        const string expected = "HelloWorld";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that newline characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceNewline()
    {
        const string input = "Hello\nWorld";
        const string expected = "Hello\\nWorld";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that carriage return characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceCarriageReturn()
    {
        const string input = "Hello\rWorld";
        const string expected = "Hello\\rWorld";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that tab characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceTab()
    {
        const string input = "Hello\tWorld";
        const string expected = "Hello\\tWorld";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that double quote characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceDoubleQuote()
    {
        const string input = "Hello\"World";
        const string expected = "Hello\\\"World";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that single quote characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceSingleQuote()
    {
        const string input = "Hello'World";
        const string expected = "Hello\\'World";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that backslash characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceBackslash()
    {
        const string input = "Hello\\World";
        const string expected = "Hello\\\\World";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that comma characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceComma()
    {
        const string input = "Hello,World";
        const string expected = "Hello\\,World";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that semicolon characters are replaced with their escaped representation.
    /// </summary>
    [Fact]
    public void ToString_ShouldReplaceSemicolon()
    {
        const string input = "Hello;World";
        const string expected = "Hello\\;World";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that a null input returns null.
    /// </summary>
    [Fact]
    public void ToString_ShouldHandleNullInput()
    {
        const string? input = null;
        Sanitized sanitizedValue = input;
        Assert.Equal(string.Empty, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that an empty string remains unchanged.
    /// </summary>
    [Fact]
    public void ToString_ShouldHandleEmptyString()
    {
        const string input = "";
        Sanitized sanitizedValue = input;
        Assert.Equal(input, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that a string with only control characters is sanitized to an empty string.
    /// </summary>
    [Fact]
    public void ToString_ShouldHandleStringWithOnlyControlCharacters()
    {
        const string input = "\x01\x02\x03";
        const string expected = "";
        Sanitized sanitizedValue = input;
        Assert.Equal(expected, sanitizedValue.ToString());
    }
}
