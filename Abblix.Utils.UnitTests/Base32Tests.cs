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
