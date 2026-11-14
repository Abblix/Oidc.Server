// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// Everything this server signs or encrypts crosses <see cref="ProfiledJwtIssuer"/>, which judges the algorithm handed
/// to the creator against the profile in force (FAPI 1.0 Part 2 sections 8.6 and 8.6.1, FAPI 2.0 section 5.4.1). Held as
/// a property of the assembly: no other type takes the creator in a constructor, so a new signing path cannot go round
/// the guard without failing here.
/// </summary>
public class OnlyTheGuardTakesTheCreatorTests
{
    /// <summary>
    /// The types allowed the creator besides the guard: two read only which algorithms the creator supports, and the
    /// security event token signer is left to issue #897.
    /// </summary>
    private static readonly Type[] Exempt =
    [
        typeof(ProfiledJwtIssuer),
        typeof(JwtAlgorithmsProvider),
        typeof(ServiceTokensAlgorithmsValidator),
        typeof(TenantSecurityEventTokenSigner),
    ];

    private static Type[] TypesTaking(Type dependency)
        => typeof(ProfiledJwtIssuer).Assembly.GetTypes()
            .Where(type => type
                .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                .Any(constructor => constructor.GetParameters().Any(parameter => parameter.ParameterType == dependency)))
            .ToArray();

    [Fact]
    public void NoTypeButTheGuard_TakesTheCreator()
    {
        var others = TypesTaking(typeof(IJsonWebTokenCreator)).Except(Exempt).Select(type => type.FullName).ToArray();

        Assert.True(others.Length == 0, $"These take IJsonWebTokenCreator past the guard: {string.Join(", ", others)}");
    }

    /// <summary>
    /// Every exemption is a type the walk finds, the guard among them, so an empty result cannot be what passes the
    /// test above and no exemption stands for a type that no longer takes the creator.
    /// </summary>
    [Fact]
    public void EachExemption_IsATypeTheWalkFinds()
    {
        var found = TypesTaking(typeof(IJsonWebTokenCreator));

        Assert.All(Exempt, type => Assert.Contains(type, found));
    }
}
