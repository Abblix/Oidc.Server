// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;

namespace Abblix.Utils.UnitTests;

public class Base32Tests
{
    private static byte[]? ToBytes(string? input)
        => input != null ? Encoding.ASCII.GetBytes(input) : null;

    [Theory]
    [InlineData(null, true,"")]
    [InlineData("", true,"")]
    [InlineData("f", true,"MY======")]
    [InlineData("fo", true,"MZXQ====")]
    [InlineData("foo", true,"MZXW6===")]
    [InlineData("foob", true,"MZXW6YQ=")]
    [InlineData("fooba", true,"MZXW6YTB")]
    [InlineData("foobar", true,"MZXW6YTBOI======")]
    [InlineData("f", false,"MY")]
    [InlineData("fo", false,"MZXQ")]
    [InlineData("foo", false,"MZXW6")]
    [InlineData("foob", false,"MZXW6YQ")]
    [InlineData("fooba", false,"MZXW6YTB")]
    [InlineData("foobar", false,"MZXW6YTBOI")]
    public void Encode(string? input, bool padding, string expected)
    {
        var actual = Base32.Encode(ToBytes(input), padding);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("MY======", "f")]
    [InlineData("MZXQ====", "fo")]
    [InlineData("MZXW6===","foo")]
    [InlineData("MZXW6YQ=", "foob")]
    [InlineData("MZXW6YTB", "fooba")]
    [InlineData("MZXW6YTBOI======", "foobar")]
    [InlineData("MY", "f")]
    [InlineData("MZXQ", "fo")]
    [InlineData("MZXW6", "foo")]
    [InlineData("MZXW6YQ", "foob")]
    [InlineData("MZXW6YTBOI", "foobar")]
    public void Decode(string? input, string expected)
    {
        var actual = Encoding.ASCII.GetString(Base32.Decode(input));
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(null, true,"")]
    [InlineData("", true,"")]
    [InlineData("f", true,"CO======")]
    [InlineData("fo", true,"CPNG====")]
    [InlineData("foo", true,"CPNMU===")]
    [InlineData("foob", true,"CPNMUOG=")]
    [InlineData("fooba", true,"CPNMUOJ1")]
    [InlineData("foobar", true,"CPNMUOJ1E8======")]
    [InlineData("f", false,"CO")]
    [InlineData("fo", false,"CPNG")]
    [InlineData("foo", false,"CPNMU")]
    [InlineData("foob", false,"CPNMUOG")]
    [InlineData("fooba", false,"CPNMUOJ1")]
    [InlineData("foobar", false,"CPNMUOJ1E8")]
    public void EncodeHex(string? input, bool padding, string expected)
    {
        var actual = Base32.EncodeHex(ToBytes(input), padding);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("CO======", "f" )]
    [InlineData("CPNG====", "fo")]
    [InlineData("CPNMU===", "foo" )]
    [InlineData("CPNMUOG=", "foob" )]
    [InlineData("CPNMUOJ1", "fooba")]
    [InlineData("CPNMUOJ1E8======", "foobar")]
    [InlineData("CO", "f" )]
    [InlineData("CPNG", "fo")]
    [InlineData("CPNMU", "foo")]
    [InlineData("CPNMUOG", "foob")]
    [InlineData("CPNMUOJ1E8", "foobar")]
    public void DecodeHex(string? input, string expected)
    {
        var actual = Encoding.ASCII.GetString(Base32.DecodeHex(input));
        Assert.Equal(expected, actual);
    }
}
