// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Oidc.UnitTests;

public class CodeChallengeTests
{
    /// <summary>
    /// The worked example of RFC 7636 Appendix B.
    /// </summary>
    [Fact]
    public void S256_MatchesTheWorkedExampleOfTheSpecification()
    {
        Assert.Equal(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallenge.Calculate(CodeChallengeMethods.S256, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    [Fact]
    public void Plain_IsTheVerifierItself()
    {
        Assert.Equal("verifier", CodeChallenge.Calculate(CodeChallengeMethods.Plain, "verifier"));
    }

    [Fact]
    public void AnUnknownMethod_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CodeChallenge.Calculate("S384", "verifier"));
    }
}
