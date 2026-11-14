// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Primitives;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// A space-separated locale list read from a form or a query names a language with every tag, as the MVC host and
/// the request object path require; a tag naming no language is a malformed value.
/// </summary>
public class FormValuesCulturesTests
{
    [Fact]
    public void EveryTagNamingALanguage_IsRead()
    {
        var cultures = FormValues.Cultures(new StringValues("en fr-CA"));

        Assert.NotNull(cultures);
        Assert.Equal(["en", "fr-CA"], cultures.Select(culture => culture.Name));
    }

    [Fact]
    public void SpacesAlone_AreAnEmptyList()
    {
        var cultures = FormValues.Cultures(new StringValues("   "));

        Assert.NotNull(cultures);
        Assert.Empty(cultures);
    }

    [Theory]
    [InlineData("und")]
    [InlineData("en und")]
    [InlineData("x-iv")]
    [InlineData("!")]
    [InlineData("en\t")]
    [InlineData("\t")]
    public void ATagNamingNoLanguage_IsAMalformedValue(string value)
        => Assert.Throws<FormatException>(() => FormValues.Cultures(new StringValues(value)));
}
