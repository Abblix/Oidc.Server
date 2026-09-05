// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// The comparison every endpoint uses to decide whether a session belongs to an end user a request named.
/// </summary>
/// <remarks>
/// Three endpoints depend on this, and each of them mocks the converter as an identity when testing its own
/// logic - which is right there and leaves this untested everywhere. What it decides is a refusal, so its
/// edges are worth pinning once, here.
/// </remarks>
public class SubjectTypeConverterExtensionsTests
{
    private const string ClientId = "client";

    private static AuthSession Session(string subject) =>
        new(subject, "session-1", DateTimeOffset.UnixEpoch, "test");

    private static ISubjectTypeConverter Converting(Func<string, string> convert)
    {
        var converter = new Mock<ISubjectTypeConverter>(MockBehavior.Strict);
        converter
            .Setup(c => c.Convert(It.IsAny<string>(), It.IsAny<ClientInfo>()))
            .Returns((string subject, ClientInfo _) => convert(subject));

        return converter.Object;
    }

    /// <summary>
    /// A session is named when the set holds the subject as this client sees it.
    /// </summary>
    /// <remarks>
    /// The conversion is what the comparison is about: a pairwise client is sent a pseudonym, so a set built
    /// from what that client sent can only match the sealed form of a session's subject.
    /// </remarks>
    [Fact]
    public void ASubjectSealedForThisClient_IsNamed()
    {
        var converter = Converting(subject => "sealed:" + subject);

        Assert.True(converter.Names(Session("alice"), ["sealed:alice"], new ClientInfo(ClientId)));
        Assert.False(converter.Names(Session("alice"), ["alice"], new ClientInfo(ClientId)));
    }

    /// <summary>
    /// Subjects differing only in case are different end users.
    /// </summary>
    /// <remarks>
    /// A subject is an opaque identifier compared octet for octet. Folding case here would let one end user
    /// be answered for under another's name wherever a store happens to be case-insensitive.
    /// </remarks>
    [Fact]
    public void ASubjectDifferingOnlyInCase_IsNotNamed()
    {
        var converter = Converting(subject => subject);

        Assert.False(converter.Names(Session("alice"), ["Alice"], new ClientInfo(ClientId)));
    }

    /// <summary>
    /// An empty set names nobody.
    /// </summary>
    /// <remarks>
    /// A request reaches this by naming a value outside its own list of values, which OpenID Connect Core
    /// 1.0 Section 5.5.1 says "MUST cause the authentication to fail". Reading it as "no constraint" is the
    /// one way this comparison could answer a request for an end user it explicitly ruled out.
    /// </remarks>
    [Fact]
    public void AnEmptySet_NamesNobody()
    {
        var converter = Converting(subject => subject);

        Assert.False(converter.Names(Session("alice"), [], new ClientInfo(ClientId)));
    }

    /// <summary>
    /// A converter that cannot seal reports no match rather than faulting.
    /// </summary>
    /// <remarks>
    /// Sealing throws when a client is registered as pairwise and the deployment configured no pairwise
    /// settings. That is a configuration fault rather than an answer about this end user, and the safe
    /// reading is the refusing one: every caller here turns "no match" into a refusal, so a misconfigured
    /// deployment stops answering rather than answering for anybody.
    /// </remarks>
    [Fact]
    public void AConverterThatCannotSeal_NamesNobody()
    {
        var converter = Converting(_ => throw new InvalidOperationException("pairwise settings are missing"));

        Assert.False(converter.Names(Session("alice"), ["alice"], new ClientInfo(ClientId)));
    }
}
