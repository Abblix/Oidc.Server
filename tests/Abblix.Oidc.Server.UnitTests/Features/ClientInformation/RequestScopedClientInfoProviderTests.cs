// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
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
}
