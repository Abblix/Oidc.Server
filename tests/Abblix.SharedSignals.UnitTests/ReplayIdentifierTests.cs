// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.SharedSignals.Receiver;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// The one property both receivers depend on and neither can check for itself: two different
/// (issuer, token) pairs never compose onto one reserved value.
/// </summary>
public class ReplayIdentifierTests
{
    /// <summary>
    /// The collision the escaping exists to prevent, written as the pair that produces it when the
    /// escaping is dropped: "https://op.example.com" with "a:b" and "https://op.example.com:a" with
    /// "b" both read as the same three parts around two separators.
    /// </summary>
    /// <remarks>
    /// Worth a test of its own because the failure is silent in the worst direction: one provider's
    /// token would reserve another provider's identifier, so a logout order that had never arrived
    /// would be refused as a replay, and nothing anywhere would report why.
    /// </remarks>
    [Fact]
    public void TwoPairsThatWouldCollideUnescaped_ComposeToDifferentValues()
    {
        var first = ReplayIdentifier.ForToken("https://op.example.com", "a:b");
        var second = ReplayIdentifier.ForToken("https://op.example.com:a", "b");

        Assert.NotEqual(first, second);
    }

    /// <summary>
    /// The control the case above needs: the same pair composes to the same value, so the
    /// inequality there says the halves are told apart rather than that nothing ever matches.
    /// </summary>
    [Fact]
    public void TheSamePair_ComposesToTheSameValue()
    {
        var first = ReplayIdentifier.ForToken("https://op.example.com", "jti-1");
        var second = ReplayIdentifier.ForToken("https://op.example.com", "jti-1");

        Assert.Equal(first, second);
    }

    /// <summary>
    /// Both halves take part: a token identifier repeated under a second issuer is a different
    /// reservation, which is what makes one provider unable to burn another's identifiers.
    /// </summary>
    [Fact]
    public void TheSameTokenIdUnderTwoIssuers_ComposesToDifferentValues()
    {
        var first = ReplayIdentifier.ForToken("https://op.example.com", "jti-1");
        var second = ReplayIdentifier.ForToken("https://other.example.com", "jti-1");

        Assert.NotEqual(first, second);
    }
}
