// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// Tests for the fail-fast salt validation in <see cref="ServiceCollectionExtensions.AddPairwiseSubjectIdentifiers"/>.
/// The salt is the sole key material of the pairwise seal, so a missing, malformed, or too-short one is rejected at
/// registration - at startup - rather than at the first token issuance or, worse, silently under a weak key.
/// </summary>
public class AddPairwiseSubjectIdentifiersTests
{
    // A valid salt: 32 zero bytes, base64-encoded.
    private static readonly string ValidSalt = Convert.ToBase64String(new byte[32]);

    [Fact]
    public void ValidSalt_RegistersSettings()
    {
        var services = new ServiceCollection();

        services.AddPairwiseSubjectIdentifiers(new PairwiseSubjectSettings { Salt = ValidSalt });

        using var provider = services.BuildServiceProvider();
        var settings = provider.GetService<PairwiseSubjectSettings>();
        Assert.NotNull(settings);
        Assert.Equal(ValidSalt, settings!.Salt);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingSalt_Throws(string salt)
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(
            () => services.AddPairwiseSubjectIdentifiers(new PairwiseSubjectSettings { Salt = salt }));
    }

    [Fact]
    public void NonBase64Salt_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(
            () => services.AddPairwiseSubjectIdentifiers(
                new PairwiseSubjectSettings { Salt = "not valid base64 !!!" }));
    }

    [Fact]
    public void TooShortSalt_Throws()
    {
        // 16 decoded bytes is below the 256-bit minimum that keys the seal securely.
        var services = new ServiceCollection();
        var shortSalt = Convert.ToBase64String(new byte[16]);

        Assert.Throws<ArgumentException>(
            () => services.AddPairwiseSubjectIdentifiers(new PairwiseSubjectSettings { Salt = shortSalt }));
    }
}
