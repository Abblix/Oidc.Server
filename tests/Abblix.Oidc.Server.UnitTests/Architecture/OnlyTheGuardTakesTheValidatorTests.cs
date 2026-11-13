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
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// Everything this server accepts crosses <see cref="ProfiledJwtValidator"/>, which stamps the validation with the
/// algorithms the profile in force admits (FAPI 1.0 Part 2 sections 8.6 and 8.6.1, FAPI 2.0 section 5.4.1). Held as a
/// property of the assembly: no other type takes the validator in a constructor.
/// </summary>
public class OnlyTheGuardTakesTheValidatorTests
{
    /// <summary>
    /// The types allowed the validator besides the guard, each reading only which algorithms the validator supports.
    /// </summary>
    private static readonly Type[] Exempt =
    [
        typeof(ProfiledJwtValidator),
        typeof(JwtAlgorithmsProvider),
        typeof(BackChannelAuthenticationValidator),
        typeof(EncryptedResponseAlgorithmsValidator),
    ];

    private static Type[] TypesTakingTheValidator()
        => typeof(ProfiledJwtValidator).Assembly.GetTypes()
            .Where(type => type
                .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                .Any(constructor => constructor.GetParameters()
                    .Any(parameter => parameter.ParameterType == typeof(IJsonWebTokenValidator))))
            .ToArray();

    [Fact]
    public void NoTypeButTheGuard_TakesTheValidator()
    {
        var others = TypesTakingTheValidator().Except(Exempt).Select(type => type.FullName).ToArray();

        Assert.True(others.Length == 0, $"These take IJsonWebTokenValidator past the guard: {string.Join(", ", others)}");
    }

    /// <summary>
    /// Every exemption is a type the walk finds, the guard among them, so an empty result cannot be what passes the
    /// test above and no exemption stands for a type that no longer takes the validator.
    /// </summary>
    [Fact]
    public void EachExemption_IsATypeTheWalkFinds()
    {
        var found = TypesTakingTheValidator();

        Assert.All(Exempt, type => Assert.Contains(type, found));
    }
}
