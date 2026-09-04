// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Jwt;
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
    public void EveryControl_CarriesItsStrictestValue()
    {
        var wrong = Controls()
            .Where(control => !Equals(
                control.GetValue(SecurityProfileRequirements.StrictestRequirements),
                StrictestValue(control.Name)))
            .Select(control => control.Name)
            .ToArray();

        Assert.True(
            wrong.Length == 0,
            $"the strictest bundle leaves a control undemanded: {string.Join(", ", wrong)}");
    }

    /// <summary>
    /// And the one flag that REMOVES a control stays off, which is the strict setting for it.
    /// Stated here as well as in the table, so that an entry deleted from the table cannot quietly
    /// turn this control into one more thing the bundle demands.
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
    /// Every control this bundle must demand carries the strictest value its type can express, and
    /// a control whose strictest value is not simply <c>true</c> is named here with the value it
    /// must hold. Named through <c>nameof</c> so a rename carries them.
    /// </summary>
    /// <remarks>
    /// The case below walks EVERY property the type declares rather than only the booleans, because
    /// a filter by type silently skips whatever is added in another shape - and the two controls
    /// carrying values, the ceiling and the tolerance, are exactly the ones a bundle can be short of
    /// while every boolean is set. A property this table does not mention has to be a boolean set to
    /// <c>true</c>, so a new control of any shape fails until somebody decides what strict means for
    /// it.
    /// </remarks>
    private static readonly Dictionary<string, object?> StrictestValues = new()
    {
        // The one flag that REMOVES a control, so demanding it would weaken the bundle.
        [nameof(SecurityProfileRequirements.ForbidRefreshTokenRotation)] = false,

        // The tightest bound and the tightest tolerance this type knows of.
        [nameof(SecurityProfileRequirements.MaxClockSkew)] = ClockSkew.Fapi2Ceiling,
        [nameof(SecurityProfileRequirements.DefaultClockSkew)] = ClockSkew.Fapi2,
    };

    /// <summary>
    /// What a named control must hold to be at its strictest: whatever the table says, and demanded
    /// otherwise. A control of any shape the table does not mention therefore fails until somebody
    /// decides what strict means for it.
    /// </summary>
    /// <param name="control">The name of the control being asked about.</param>
    private static object StrictestValue(string control)
        => StrictestValues.TryGetValue(control, out var expected) ? expected! : Demanded;

    /// <summary>
    /// The strictest value of an ordinary control, which is one that is demanded.
    /// </summary>
    private const bool Demanded = true;

    /// <summary>
    /// Every control the type declares, which is what makes this a property of the TYPE rather than
    /// a list kept in step by hand.
    /// </summary>
    private static System.Reflection.PropertyInfo[] Controls()
        => typeof(SecurityProfileRequirements).GetProperties();

    /// <summary>
    /// The enumeration above finds something, so an empty set cannot be what makes the first case
    /// pass. A filter that matched nothing would report every control demanded over no controls.
    /// </summary>
    [Fact]
    public void TheControlsAreFound()
    {
        Assert.NotEmpty(Controls());
    }

    /// <summary>
    /// And the table names only controls that exist, so a rename cannot leave an entry standing over
    /// nothing while the case above goes on passing.
    /// </summary>
    [Fact]
    public void TheTableNamesOnlyRealControls()
    {
        var names = Controls().Select(control => control.Name).ToHashSet();

        Assert.All(StrictestValues.Keys, name => Assert.Contains(name, names));
    }
}
