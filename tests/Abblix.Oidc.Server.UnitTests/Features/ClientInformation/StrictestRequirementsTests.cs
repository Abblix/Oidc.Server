// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// The bundle a profile value nothing can interpret resolves to. It is reached only by a value the
/// enum does not define, which arrives from a configuration binder taking a number outside the range
/// or from a client store the host writes - so no ordinary test path reaches it, and a flag added to
/// the type and forgotten here would leave the strictest answer quietly short of one control.
/// </summary>
public class StrictestRequirementsTests
{
    /// <summary>
    /// Every tightening flag on the type is set, stated as a property over the type's own members
    /// rather than as a list somebody keeps in step by hand. A new flag arrives in this test the
    /// moment it is declared, which is the whole point: a list would go on passing without it.
    /// </summary>
    [Fact]
    public void EveryTighteningFlag_IsSet()
    {
        var unset = TighteningFlags()
            .Where(flag => !(bool)flag.GetValue(SecurityProfileRequirements.StrictestRequirements)!)
            .Select(flag => flag.Name)
            .ToArray();

        Assert.True(
            unset.Length == 0,
            $"the strictest bundle leaves a control undemanded: {string.Join(", ", unset)}");
    }

    /// <summary>
    /// And the one flag that REMOVES a control stays off, which is the strict setting for it.
    /// Without this case the assertion above could be satisfied by turning everything on, which
    /// would weaken the bundle it is meant to strengthen.
    /// </summary>
    [Fact]
    public void TheRelaxingFlag_IsNotSet()
    {
        Assert.False(SecurityProfileRequirements.StrictestRequirements.ForbidRefreshTokenRotation);
    }

    /// <summary>
    /// The bundle is what an undefined value resolves to, which is the only way anything reaches it.
    /// Asserting the flags without this leaves the object correct and unreachable.
    /// </summary>
    [Fact]
    public void AnUndefinedProfile_ResolvesToIt()
    {
        Assert.Same(
            SecurityProfileRequirements.StrictestRequirements,
            SecurityProfileRequirements.Resolve((ClientSecurityProfile)int.MaxValue));
    }

    /// <summary>
    /// The tightening flags: every boolean the type declares except the single one that removes a
    /// control. Named through <c>nameof</c> so a rename carries it, and derived from the type rather
    /// than written out, so the set cannot fall behind the type.
    /// </summary>
    private static System.Reflection.PropertyInfo[] TighteningFlags()
        => typeof(SecurityProfileRequirements)
            .GetProperties()
            .Where(property => property.PropertyType == typeof(bool))
            .Where(property => property.Name != nameof(SecurityProfileRequirements.ForbidRefreshTokenRotation))
            .ToArray();

    /// <summary>
    /// The enumeration above finds something, so an empty set cannot be what makes the first case
    /// pass. A filter that matched nothing would report every control demanded over no controls.
    /// </summary>
    [Fact]
    public void TheFlagsAreFound()
    {
        Assert.NotEmpty(TighteningFlags());
    }
}
