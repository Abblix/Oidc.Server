// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Introspection;

/// <summary>
/// RFC 8693 section 4.1: "When included as a top-level member of an OAuth token introspection response, "act" has
/// the same semantics and format as the claim of the same name." Every authorized caller learns that a token is a
/// delegation; who acts is told to it as the subject is - under the caller's own pseudonym, or not at all.
/// </summary>
public class IntrospectionActorTests
{
    private const string RealSubject = "real-user";
    private const string CurrentActor = "current-actor";
    private const string PriorActor = "prior-actor";
    private const string OwnerId = "owner";
    private const string CallerId = "caller";

    private readonly SubjectTypeConverter _converter =
        new(new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });

    private static ClientInfo Client(string clientId, bool pairwise) => new(clientId)
    {
        SubjectType = pairwise ? SubjectTypes.Pairwise : SubjectTypes.Public,
        SectorIdentifier = $"{clientId}.example.com",
    };

    /// <summary>
    /// A pairwise caller other than the token's client gets every actor of the chain sealed for its own sector,
    /// whatever the owner's subject type: each is opened against the owner first.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task APairwiseCaller_SeesEveryActorUnderItsOwnPseudonym(bool ownerPairwise)
    {
        var owner = Client(OwnerId, ownerPairwise);
        var caller = Client(CallerId, pairwise: true);

        var response = await IntrospectAsync(owner, caller);

        var act = Assert.IsType<JsonObject>(response[IanaClaimTypes.Act]);
        Assert.Equal(_converter.Convert(CurrentActor, caller), act[IanaClaimTypes.Sub]!.GetValue<string>());
        Assert.Equal(_converter.Convert(PriorActor, caller), act[IanaClaimTypes.Act]![IanaClaimTypes.Sub]!.GetValue<string>());
        Assert.Equal(_converter.Convert(RealSubject, caller), response[IanaClaimTypes.Sub]!.GetValue<string>());
    }

    /// <summary>
    /// A caller other than the token's client that is not pairwise is told no subject, so it is told no actor
    /// either; it still learns the token is a delegation, and how deep the chain is.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task APublicCaller_LearnsOfTheDelegation_WithoutAnyIdentifier(bool ownerPairwise)
    {
        var owner = Client(OwnerId, ownerPairwise);
        var caller = Client(CallerId, pairwise: false);

        var response = await IntrospectAsync(owner, caller);

        var act = Assert.IsType<JsonObject>(response[IanaClaimTypes.Act]);
        Assert.Null(act[IanaClaimTypes.Sub]);
        var prior = Assert.IsType<JsonObject>(act[IanaClaimTypes.Act]);
        Assert.Null(prior[IanaClaimTypes.Sub]);
        Assert.Null(response[IanaClaimTypes.Sub]);
    }

    /// <summary>
    /// The token's own client gets the actors as its token carries them: the pseudonyms of its own sector.
    /// </summary>
    [Fact]
    public async Task TheTokensOwnClient_SeesTheActorsAsItsTokenCarriesThem()
    {
        var owner = Client(OwnerId, pairwise: true);

        var response = await IntrospectAsync(owner, owner);

        var act = Assert.IsType<JsonObject>(response[IanaClaimTypes.Act]);
        Assert.Equal(_converter.Convert(CurrentActor, owner), act[IanaClaimTypes.Sub]!.GetValue<string>());
    }

    private async Task<JsonObject> IntrospectAsync(ClientInfo owner, ClientInfo caller)
    {
        var processor = new IntrospectionRequestProcessor(new FixedSubjectTypeConverter(_converter));

        var token = new JsonWebToken();
        token.Payload.Subject = _converter.Convert(RealSubject, owner);
        token.Payload.ClientId = OwnerId;
        token.Payload.Json[IanaClaimTypes.Act] = new JsonObject
        {
            [IanaClaimTypes.Sub] = _converter.Convert(CurrentActor, owner),
            [IanaClaimTypes.Act] = new JsonObject { [IanaClaimTypes.Sub] = _converter.Convert(PriorActor, owner) },
        };
        var request = new ValidIntrospectionRequest(
            new IntrospectionRequest { Token = "token", TokenTypeHint = TokenTypeHints.AccessToken },
            caller,
            token,
            caller.ClientId == OwnerId ? null : owner);

        var result = await processor.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out var success));
        return success.Claims.NotNull(nameof(success.Claims));
    }
}
