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
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// The salt that keys the pairwise seal is judged where it is WIRED, and both ways of wiring it judge it.
/// </summary>
/// <remarks>
/// <para>
/// A host either hands over an instance it built in code or binds a section and lets the options pipeline
/// carry it. Those need different judges. The instance overload judges its argument on the spot, because
/// there is no pipeline to hang a validator on. Settings the host bound are judged by a validator when the
/// host starts, before the service that opens the port.
/// </para>
/// <para>
/// The value itself does not refuse on assignment, and that is deliberate: the configuration binder assigns
/// by reflection, so a refusal there reaches the host wrapped in a TargetInvocationException naming
/// reflection rather than the setting - and it fires before any validator can say which rule failed.
/// </para>
/// <para>
/// What makes both necessary is that neither sees the other's instances. The extension registers with
/// TryAddSingleton, so a host that brought its own keeps it; and `required` is a rule of the compiler, so a
/// section without the key binds to a null salt with nothing raised.
/// </para>
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

    /// <summary>Each way a salt can be unusable is refused where the instance is handed over.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not base64 !!!")]

    // 16 decoded bytes is below the 256-bit minimum that keys the seal securely.
    [InlineData("AAAAAAAAAAAAAAAAAAAAAA==")]
    public void AnUnusableSalt_IsRefusedWhereItIsWired(string salt)
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(
            () => services.AddPairwiseSubjectIdentifiers(new PairwiseSubjectSettings { Salt = salt }));
    }

    /// <summary>The floor is 256 bits, and one byte under it is refused.</summary>
    /// <remarks>
    /// A case one byte below and one at the boundary, because a fixture far under the floor is satisfied by
    /// any threshold between it and the real one - the rule would read as pinned while the number moved.
    /// </remarks>
    [Theory]
    [InlineData(31, false)]
    [InlineData(32, true)]
    public void TheFloorIsTwoHundredAndFiftySixBits(int bytes, bool accepted)
    {
        var services = new ServiceCollection();
        var settings = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[bytes]) };

        if (accepted)
        {
            services.AddPairwiseSubjectIdentifiers(settings);

            using var provider = services.BuildServiceProvider();
            Assert.Equal(settings.Salt, provider.GetRequiredService<PairwiseSubjectSettings>().Salt);
        }
        else
        {
            Assert.Throws<ArgumentException>(() => services.AddPairwiseSubjectIdentifiers(settings));
        }
    }

    /// <summary>A salt the configuration binder never set is refused where the instance is handed over.</summary>
    /// <remarks>
    /// <c>required</c> is a rule of the compiler. The binder constructs the object and then assigns only the
    /// properties whose keys are present, so an absent key leaves a null seal key with nothing raised -
    /// measured, not assumed. A host that binds a section itself and passes the result reaches this.
    /// </remarks>
    [Fact]
    public void ASaltTheBinderNeverSet_IsRefusedAtRegistration()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Pairwise:HashAlgorithm"] = "SHA384" })
            .Build();

        var bound = configuration.GetSection("Pairwise").Get<PairwiseSubjectSettings>();

        // The control: the binder really did build one, so what follows is about the salt rather than about a
        // section that bound to nothing.
        Assert.NotNull(bound);
        Assert.Null(bound!.Salt);

        Assert.Throws<ArgumentException>(
            () => new ServiceCollection().AddPairwiseSubjectIdentifiers(bound));
    }

    /// <summary>A host that registered its own settings keeps them.</summary>
    /// <remarks>
    /// This is why a check over the extension's ARGUMENT cannot be the only one: what it judged is not
    /// necessarily what the seal is keyed with.
    /// </remarks>
    [Fact]
    public void AHostsOwnSettings_Win()
    {
        var hosts = new PairwiseSubjectSettings { Salt = ValidSalt };
        var services = new ServiceCollection();
        services.AddSingleton(hosts);

        services.AddPairwiseSubjectIdentifiers(
            new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[64]) });

        using var provider = services.BuildServiceProvider();
        Assert.Same(hosts, provider.GetRequiredService<PairwiseSubjectSettings>());
    }

    /// <summary>Settings the host bound are judged when the host starts, not when a token is minted.</summary>
    /// <remarks>
    /// <para>
    /// The options pipeline runs its validators before the host starts the service that opens the port, so a
    /// deployment whose seal key will not do never serves a request. Reaching the container instead, it
    /// surfaces as a 500 from the token endpoint the first time a pairwise identifier is minted - which names
    /// neither the setting nor the deployment that changed it.
    /// </para>
    /// <para>
    /// The refusal carries the rule's own sentence rather than a generic one, because the operator reading it
    /// has to find a line in a file: missing, not base64 and too short are three different searches.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(null, "is required")]
    [InlineData("not base64 !!!", "base64-encoded")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAA==", "at least 32 bytes")]
    public void SettingsBoundByTheHost_AreJudgedWhenItStarts(string? salt, string expected)
    {
        // A key set to null still EXISTS, and the binder assigns what exists. The absent case is spelled as
        // an absent key rather than as a null value, because those are different inputs.
        var section = salt is null
            ? new Dictionary<string, string?> { ["Pairwise:HashAlgorithm"] = "SHA256" }
            : new Dictionary<string, string?> { ["Pairwise:Salt"] = salt };

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(section).Build();

        var services = new ServiceCollection();
        services.Configure<PairwiseSubjectSettings>(configuration.GetSection("Pairwise"));
        services.AddPairwiseSubjectIdentifiers();

        using var provider = services.BuildServiceProvider();

        // What ValidateOnStart runs at startup, reached here the way the host reaches it.
        var refused = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<PairwiseSubjectSettings>>().Value);

        Assert.Contains(expected, refused.Message, StringComparison.Ordinal);
    }

    /// <summary>The control: a usable key starts, and the container hands out what was judged.</summary>
    /// <remarks>
    /// Without it the cases above are satisfied by a validator that refuses everything, and by a wiring that
    /// registers nothing at all.
    /// </remarks>
    [Fact]
    public void SettingsBoundByTheHost_AreWhatTheContainerHandsOut()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Pairwise:Salt"] = ValidSalt })
            .Build();

        var services = new ServiceCollection();
        services.Configure<PairwiseSubjectSettings>(configuration.GetSection("Pairwise"));
        services.AddPairwiseSubjectIdentifiers();

        using var provider = services.BuildServiceProvider();

        Assert.Equal(ValidSalt, provider.GetRequiredService<PairwiseSubjectSettings>().Salt);
    }
}
