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
using Abblix.Oidc.Server.Features.Licensing;
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
    /// The types allowed the validator besides the guard: the licence is signed by Abblix and judged by its own rules,
    /// and the other three read only which algorithms the validator supports.
    /// </summary>
    private static readonly string[] Exempt =
    [
        nameof(ProfiledJwtValidator),
        nameof(LicenseLoader),
        nameof(JwtAlgorithmsProvider),
        nameof(BackChannelAuthenticationValidator),
        nameof(EncryptedResponseAlgorithmsValidator),
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
        var others = TypesTakingTheValidator().Select(type => type.Name).Except(Exempt).ToArray();

        Assert.True(others.Length == 0, $"These take IJsonWebTokenValidator past the guard: {string.Join(", ", others)}");
    }

    /// <summary>
    /// The walk finds what it looks for, so an empty result cannot be what passes the test above.
    /// </summary>
    [Fact]
    public void TheWalk_FindsTheGuard()
    {
        Assert.Contains(typeof(ProfiledJwtValidator), TypesTakingTheValidator());
    }
}
