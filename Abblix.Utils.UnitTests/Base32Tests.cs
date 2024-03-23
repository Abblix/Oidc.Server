// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
