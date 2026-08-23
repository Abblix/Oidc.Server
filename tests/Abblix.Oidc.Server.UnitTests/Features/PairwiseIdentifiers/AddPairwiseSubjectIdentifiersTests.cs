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
/// The salt that keys the pairwise seal is judged by <see cref="PairwiseSubjectSettings"/> itself, so an
/// unusable one is refused wherever it is written rather than by one of the hands it passes through.
/// </summary>
/// <remarks>
/// <see cref="ServiceCollectionExtensions.AddPairwiseSubjectIdentifiers"/> registers its argument with
/// <c>TryAddSingleton</c>, which means a host that pre-registered its own instance keeps it. A check placed
/// at that extension therefore judges the copy nobody ends up using: it reads as "a weak seal key fails at
/// startup" and is not that. On the type there is no unvalidated instance to hold, whichever path builds it -
/// an object initialiser, a <c>with</c> expression, or configuration binding.
/// </remarks>
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

    /// <summary>Each way a salt can be unusable is refused by the value, before anybody is handed it.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not valid base64 !!!")]

    // 16 decoded bytes is below the 256-bit minimum that keys the seal securely.
    [InlineData("AAAAAAAAAAAAAAAAAAAAAA==")]
    public void AnUnusableSalt_IsRefusedByTheValue(string salt)
    {
        var refused = Assert.Throws<ArgumentException>(
            () => new PairwiseSubjectSettings { Salt = salt });

        Assert.Equal("salt", refused.ParamName);
    }

    /// <summary>
    /// A host registering its own settings cannot smuggle an unusable salt past the extension.
    /// </summary>
    /// <remarks>
    /// This is the case a check at the extension could not see. The host's instance wins the
    /// <c>TryAddSingleton</c>, so whatever was judged about the ARGUMENT says nothing about what the seal is
    /// keyed with - and it is the one the server actually uses. Building the value is now where it fails, so
    /// the host never reaches the registration at all.
    /// </remarks>
    [Fact]
    public void AHostsOwnSettings_CannotCarryAnUnusableSalt()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(
            () => services.AddSingleton(new PairwiseSubjectSettings { Salt = "too-short" }));

        // The control: the same registration with a usable salt goes through and is what the container holds,
        // so the refusal above is about the value rather than about pre-registering at all.
        services.AddSingleton(new PairwiseSubjectSettings { Salt = ValidSalt });
        services.AddPairwiseSubjectIdentifiers(
            new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[64]) });

        using var provider = services.BuildServiceProvider();
        Assert.Equal(ValidSalt, provider.GetRequiredService<PairwiseSubjectSettings>().Salt);
    }

    /// <summary>A `with` expression re-runs the judgement, so a copy cannot weaken the original.</summary>
    [Fact]
    public void ACopyThatWeakensTheSalt_IsRefused()
    {
        var settings = new PairwiseSubjectSettings { Salt = ValidSalt };

        Assert.Throws<ArgumentException>(() => settings with { Salt = "AAAA" });
    }
}
