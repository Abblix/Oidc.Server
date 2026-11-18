// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// The settings refused at startup once the host turns client metadata documents on.
/// </summary>
public class ClientIdMetadataDocumentOptionsValidatorTests
{
    private static bool Valid(ClientIdMetadataDocumentOptions settings, bool enabled = true)
    {
        settings.Enabled = enabled;
        return new ClientIdMetadataDocumentOptionsValidator()
            .Validate(null, new OidcOptions { ClientIdMetadataDocuments = settings })
            .Succeeded;
    }

    [Fact]
    public void TheDefaults_AreAccepted() => Assert.True(Valid(new ClientIdMetadataDocumentOptions()));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ADocumentSizeOfNothing_IsRefused(int size)
        => Assert.False(Valid(new ClientIdMetadataDocumentOptions { MaxDocumentSize = size }));

    [Fact]
    public void ANegativeMinimum_IsRefused()
        => Assert.False(Valid(new ClientIdMetadataDocumentOptions { MinimumCacheDuration = TimeSpan.FromSeconds(-1) }));

    [Fact]
    public void AMaximumBelowTheMinimum_IsRefused()
        => Assert.False(Valid(new ClientIdMetadataDocumentOptions
        {
            MinimumCacheDuration = TimeSpan.FromMinutes(10),
            MaximumCacheDuration = TimeSpan.FromMinutes(5),
        }));

    [Fact]
    public void NoHolding_IsAccepted()
        => Assert.True(Valid(new ClientIdMetadataDocumentOptions
        {
            MinimumCacheDuration = TimeSpan.Zero,
            MaximumCacheDuration = TimeSpan.Zero,
        }));

    [Theory]
    [InlineData("https://apps.example.com/", true)]
    [InlineData("https://example.com/clients/", true)]
    [InlineData("https://apps.example.com", false)]
    [InlineData("https://example.com/clients", false)]
    [InlineData("http://apps.example.com/", false)]
    [InlineData("https://user@apps.example.com/", false)]
    [InlineData("https://apps.example.com/?x=/", false)]
    [InlineData("https://apps.example.com/#/", false)]
    [InlineData("https://Apps.example.com/", false)]
    [InlineData("https://apps.example.com:443/", false)]
    [InlineData("apps.example.com/", false)]
    public void APrefix_IsAcceptedOnlyInTheFormAClientIdentifierTakes(string prefix, bool accepted)
        => Assert.Equal(accepted, Valid(new ClientIdMetadataDocumentOptions { AllowedClientIdPrefixes = [prefix] }));

    [Fact]
    public void AnEmptyAllowList_IsRefused()
        => Assert.False(Valid(new ClientIdMetadataDocumentOptions { AllowedClientIdPrefixes = [] }));

    [Fact]
    public void SettingsOfAServerNotResolvingDocuments_AreNotJudged()
        => Assert.True(Valid(new ClientIdMetadataDocumentOptions { MaxDocumentSize = 0 }, enabled: false));
}
