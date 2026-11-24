// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// One request asks the store once per client it names, whatever the answer, and the next request asks again.
/// </summary>
public sealed class RequestScopedClientInfoProviderTests
{
    private const string ClientId = "https://client.example.com/metadata.json";

    private static readonly TenantDefinition Tenant = new TestIssuer().ToTenant();

    private readonly Mock<IClientInfoProvider> _store = new(MockBehavior.Strict);

    private void Answer(Result<ClientInfo, ClientAbsence> answer)
        => _store.Setup(store => store.FindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(answer);

    public static TheoryData<int> Answers => [0, 1, 2, 3];

    private static Result<ClientInfo, ClientAbsence> AnswerAt(int index) => index switch
    {
        0 => new ClientInfo(ClientId),
        1 => ClientAbsence.Unknown,
        2 => ClientAbsence.Refused,
        3 => ClientAbsence.TemporarilyUnavailable,
        _ => throw new System.ArgumentOutOfRangeException(nameof(index), index, null),
    };

    [Theory]
    [MemberData(nameof(Answers))]
    public async Task EveryStepOfOneRequest_GetsTheFirstAnswer_AskedOnce(int index)
    {
        var answer = AnswerAt(index);
        Answer(answer);
        var clients = new RequestScopedClientInfoProvider(_store.Object);

        for (var step = 0; step < 3; step++)
            Assert.Equal(answer, await clients.FindClientAsync(Tenant, ClientId));

        _store.Verify(store => store.FindClientAsync(TestTenant.Matched, ClientId), Times.Once);
    }

    [Theory]
    [MemberData(nameof(Answers))]
    public async Task TheNextRequest_AsksAgain(int index)
    {
        Answer(AnswerAt(index));

        await new RequestScopedClientInfoProvider(_store.Object).FindClientAsync(Tenant, ClientId);
        await new RequestScopedClientInfoProvider(_store.Object).FindClientAsync(Tenant, ClientId);

        _store.Verify(store => store.FindClientAsync(TestTenant.Matched, ClientId), Times.Exactly(2));
    }

    /// <summary>
    /// A request is refused as one whose client could not be had for now only where a client it named was answered
    /// so: draft-ietf-oauth-client-id-metadata-document-03 section 6.1 tells a transient failure from a terminal one.
    /// </summary>
    [Theory]
    [MemberData(nameof(Answers))]
    public async Task TheUnavailableClientRefusal_FollowsOnlyATemporarilyUnavailableAnswer(int index)
    {
        Answer(AnswerAt(index));
        _store
            .Setup(store => store.FindClientAsync(TestTenant.Matched, "other"))
            .ReturnsAsync(ClientAbsence.Unknown);
        var clients = new RequestScopedClientInfoProvider(_store.Object);

        Assert.Null(clients.UnavailableClientRefusal());
        await clients.FindClientAsync(Tenant, "other");
        await clients.FindClientAsync(Tenant, ClientId);

        Assert.Equal(index == 3, clients.UnavailableClientRefusal() is not null);
    }

    /// <summary>
    /// A refusal of a request that met a client it could not have for now is answered as that, except a request using
    /// more than one authentication method, which RFC 6749 section 5.2 names an invalid_request whatever else it met.
    /// </summary>
    [Theory]
    [MemberData(nameof(Answers))]
    public async Task ARefusal_IsTheUnavailableClientRefusal_OnlyAfterATemporarilyUnavailableAnswer(int index)
    {
        Answer(AnswerAt(index));
        var clients = new RequestScopedClientInfoProvider(_store.Object);
        await clients.FindClientAsync(Tenant, ClientId);
        var refusal = new OidcError(ErrorCodes.InvalidGrant, "refused");
        var moreThanOneMethod = new MoreThanOneClientAuthenticationMethodError("two methods");

        Assert.Equal(index == 3, clients.RefusalOf(refusal) is ClientTemporarilyUnavailableError);
        Assert.Same(moreThanOneMethod, clients.RefusalOf(moreThanOneMethod));
    }

    /// <summary>
    /// An outcome standing for a refusal though it is a success - a token revoked or reported on without its client -
    /// is answered as the refusal of a client that could not be had for now, as a refusal is.
    /// </summary>
    [Theory]
    [MemberData(nameof(Answers))]
    public async Task AnyOutcome_IsTheUnavailableClientRefusal_OnlyAfterATemporarilyUnavailableAnswer(int index)
    {
        Answer(AnswerAt(index));
        var clients = new RequestScopedClientInfoProvider(_store.Object);
        await clients.FindClientAsync(Tenant, ClientId);

        var success = clients.AnswerOf<string>("answered");
        var refusal = clients.AnswerOf<string>(new OidcError(ErrorCodes.InvalidRequest, "refused"));
        var moreThanOneMethod = clients.AnswerOf<string>(new MoreThanOneClientAuthenticationMethodError("two"));

        Assert.Equal(index == 3, success.TryGetFailure(out var instead) && instead is ClientTemporarilyUnavailableError);
        Assert.Equal(index == 3, refusal.TryGetFailure(out var failure) && failure is ClientTemporarilyUnavailableError);
        Assert.True(moreThanOneMethod.TryGetFailure(out var kept) && kept is MoreThanOneClientAuthenticationMethodError);
    }
}
