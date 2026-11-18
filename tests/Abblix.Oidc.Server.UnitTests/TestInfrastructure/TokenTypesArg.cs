// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using Abblix.Jwt;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Matches the token types a call site hands to a mocked JWT validator, for a test that pins which types that site
/// accepts.
/// </summary>
/// <remarks>
/// The policy's own equality compares its list of types by reference, so a policy built in the test never equals
/// the one the site built; this compares the rule and the types themselves, in order.
/// </remarks>
public static class TokenTypesArg
{
    /// <summary>
    /// Matches a policy with the same rule and the same types as <paramref name="expected"/>.
    /// </summary>
    public static TokenTypePolicy Is(TokenTypePolicy expected) => Match.Create<TokenTypePolicy>(
        actual => actual.Rule == expected.Rule && actual.Types.SequenceEqual(expected.Types));
}
