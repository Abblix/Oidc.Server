// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// The salt that keys the pairwise seal is judged by <see cref="PairwiseSubjectSettings"/> itself, so an
/// unusable one is refused wherever it is written rather than by one of the hands it passes through.
/// </summary>
/// <remarks>
/// Two judges, because they answer about different instances. The property covers everything somebody WRITES,
/// which the extension cannot: it registers with <c>TryAddSingleton</c>, so a host's own instance wins and
/// what the extension saw was a copy nobody uses. The extension covers what the configuration binder BUILDS,
/// which the property cannot: the binder sets only the properties whose keys are present, so an absent one
/// never reaches an accessor - <c>required</c> is a compiler rule, not a runtime one.
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
        Assert.Throws<ArgumentException>(() => new PairwiseSubjectSettings { Salt = salt });

    }

    /// <summary>
    /// A host registering its own settings cannot smuggle an unusable salt past the extension.
    /// </summary>
    /// <remarks>
    /// The host's instance wins the <c>TryAddSingleton</c>, so what the extension judges about its ARGUMENT
    /// says nothing about the key the seal actually uses. Assignment is where this one fails, so the host
    /// never reaches the registration with it.
    /// </remarks>
    [Fact]
    public void AHostsOwnSettings_CannotCarryAnUnusableSalt()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(
            () => services.AddSingleton(new PairwiseSubjectSettings { Salt = "not base64 !!!" }));

        // The control: the same registration with a usable salt goes through and is what the container holds,
        // so the refusal above is about the value rather than about pre-registering at all.
        services.AddSingleton(new PairwiseSubjectSettings { Salt = ValidSalt });
        services.AddPairwiseSubjectIdentifiers(
            new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[64]) });

        using var provider = services.BuildServiceProvider();
        Assert.Equal(ValidSalt, provider.GetRequiredService<PairwiseSubjectSettings>().Salt);
    }

    /// <summary>
    /// A salt the configuration binder never set is refused at registration.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the shape the property alone cannot judge. <c>required</c> is a compiler rule; the binder
    /// constructs the object and then sets only the properties whose keys are present, so an absent
    /// <c>Pairwise:Salt</c> never enters the accessor and the instance carries a null seal key with nothing
    /// raised. Measured, not assumed: the accessor is invoked zero times for that input.
    /// </para>
    /// <para>
    /// Reaching the container that way, it surfaces as a 500 from the token endpoint the first time a
    /// pairwise identifier is minted - the failure a startup check exists to move.
    /// </para>
    /// </remarks>
    [Fact]
    public void ASaltTheBinderNeverSet_IsRefusedAtRegistration()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Pairwise:HashAlgorithm"] = "SHA384" })
            .Build();

        var bound = configuration.GetSection("Pairwise").Get<PairwiseSubjectSettings>();

        // The control: the binder really did build one, so what follows is about the salt rather than about
        // a section that bound to nothing.
        Assert.NotNull(bound);
        Assert.Null(bound!.Salt);

        Assert.Throws<ArgumentException>(
            () => new ServiceCollection().AddPairwiseSubjectIdentifiers(bound));
    }

    /// <summary>The floor is 256 bits, and one byte under it is refused.</summary>
    /// <remarks>
    /// A case one byte below and one byte at the boundary, because a fixture far under the floor is satisfied
    /// by any threshold between it and the real one - the rule would read as pinned while the number moved.
    /// </remarks>
    [Theory]
    [InlineData(31, false)]
    [InlineData(32, true)]
    public void TheFloorIsTwoHundredAndFiftySixBits(int bytes, bool accepted)
    {
        var salt = Convert.ToBase64String(new byte[bytes]);

        if (accepted)
        {
            Assert.Equal(salt, new PairwiseSubjectSettings { Salt = salt }.Salt);
        }
        else
        {
            Assert.Throws<ArgumentException>(() => new PairwiseSubjectSettings { Salt = salt });
        }
    }

    /// <summary>A `with` expression re-runs the judgement, so a copy cannot weaken the original.</summary>
    [Fact]
    public void ACopyThatWeakensTheSalt_IsRefused()
    {
        var settings = new PairwiseSubjectSettings { Salt = ValidSalt };

        Assert.Throws<ArgumentException>(() => settings with { Salt = "AAAA" });
    }
}
