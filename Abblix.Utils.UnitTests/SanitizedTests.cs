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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
        Assert.Equal(expected, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that a null input returns null.
    /// </summary>
    [Fact]
    public void ToString_ShouldHandleNullInput()
    {
        const string? input = null;
        var sanitizedValue = new Sanitized(input);
        Assert.Equal(string.Empty, sanitizedValue.ToString());
    }

    /// <summary>
    /// Tests that an empty string remains unchanged.
    /// </summary>
    [Fact]
    public void ToString_ShouldHandleEmptyString()
    {
        const string input = "";
        var sanitizedValue = new Sanitized(input);
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
        var sanitizedValue = new Sanitized(input);
        Assert.Equal(expected, sanitizedValue.ToString());
    }
}
