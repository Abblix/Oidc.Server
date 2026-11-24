// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// RFC 9700 section 4.15.1: a client registering itself does not choose its client_id unless the host lets it, and an
/// RFC 7592 update keeps the client_id it carries.
/// </summary>
public class ProposedClientIdValidatorTests
{
    private const string Proposed = "proposed-client";

    private static async Task<ClientRegistrationValidationContext> RunAsync(
        DynamicClientOperation operation,
        bool acceptProposedClientId)
    {
        var options = new Mock<IOptionsMonitor<OidcOptions>>();
        options.Setup(monitor => monitor.CurrentValue).Returns(new OidcOptions
        {
            NewClientOptions = new NewClientOptions { AcceptProposedClientId = acceptProposedClientId },
        });
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest { ClientId = Proposed })
        {
            Operation = operation,
        };

        Assert.Null(await new ProposedClientIdValidator(options.Object).ValidateAsync(SingleIssuer.Tenant, context));
        return context;
    }

    [Fact]
    public async Task ARegistrationsProposal_IsDroppedByDefault()
        => Assert.Null((await RunAsync(DynamicClientOperation.Register, acceptProposedClientId: false)).Request.ClientId);

    [Fact]
    public async Task ARegistrationsProposal_IsKeptWhereTheHostAcceptsProposals()
        => Assert.Equal(
            Proposed,
            (await RunAsync(DynamicClientOperation.Register, acceptProposedClientId: true)).Request.ClientId);

    [Fact]
    public async Task AnUpdatesClientId_IsKept()
        => Assert.Equal(
            Proposed,
            (await RunAsync(DynamicClientOperation.Update, acceptProposedClientId: false)).Request.ClientId);
}
