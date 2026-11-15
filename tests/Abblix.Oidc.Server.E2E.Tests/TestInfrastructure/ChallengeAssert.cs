// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Holds a challenge, read by the challenge grammar, to its whole set of parameters, so a parameter added where none
/// belongs fails the test as a missing one does.
/// </summary>
internal static class ChallengeAssert
{
    /// <summary>
    /// The challenge advertises <paramref name="scheme"/> and carries exactly the parameters of
    /// <paramref name="expected"/>. A null value stands for a parameter whose wording is not compared, such as
    /// error_description, which must still be present and not empty.
    /// </summary>
    public static void Carries(
        ChallengeReader.Challenge challenge,
        string scheme,
        params (string Name, string? Value)[] expected)
    {
        Assert.Equal(scheme, challenge.Scheme);
        Assert.Equal(
            expected.Select(parameter => parameter.Name).Order(StringComparer.Ordinal),
            challenge.Parameters.Keys.Order(StringComparer.Ordinal));

        foreach (var (name, value) in expected)
        {
            if (value is null)
                Assert.False(string.IsNullOrEmpty(challenge.Parameters[name]), $"{name} is empty");
            else
                Assert.Equal(value, challenge.Parameters[name]);
        }
    }
}
