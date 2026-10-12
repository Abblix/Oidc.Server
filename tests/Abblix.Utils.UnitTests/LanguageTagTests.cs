// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils.UnitTests;

/// <summary>
/// A language tag names a culture only when .NET knows the name and the culture it builds has a name of its own; a
/// tag such as <c>und</c>, which builds a culture with no name, names no language a page can be shown in.
/// </summary>
public class LanguageTagTests
{
    [Theory]
    [InlineData("en", "en")]
    [InlineData("fr-CA", "fr-CA")]
    [InlineData("EN-us", "en-US")]
    public void ATagNamingALanguage_IsThatCulture(string tag, string name)
    {
        Assert.True(LanguageTag.TryParse(tag, out var culture));
        Assert.Equal(name, culture.Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("und")]
    [InlineData("x-iv")]
    [InlineData("!")]
    [InlineData("en_US!")]
    public void ATagNamingNoLanguage_IsRefused(string tag)
        => Assert.False(LanguageTag.TryParse(tag, out _));
}
