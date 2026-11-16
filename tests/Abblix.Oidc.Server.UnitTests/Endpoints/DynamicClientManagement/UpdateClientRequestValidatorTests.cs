// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// An update keeps the sector the pairwise subjects of the client's end users are computed under.
/// </summary>
public class UpdateClientRequestValidatorTests
{
    private const string ClientId = "client";
    private const string StoredSector = "client.example.com";

    [Theory]
    [InlineData("other.example.com")]
    [InlineData(null)]
    public async Task AnUpdateDerivingAnotherSector_IsRefused(string? derivedSector)
    {
        var result = await Validator(derivedSector).ValidateAsync(SingleIssuer.Tenant, Update());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    [Fact]
    public async Task AnUpdateKeepingTheSector_IsAccepted()
    {
        var result = await Validator(StoredSector).ValidateAsync(SingleIssuer.Tenant, Update());

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// RFC 7592 section 2.2: the body's client_id "MUST be the same as its currently issued client identifier". An
    /// invalid field is answered with the RFC 7591 section 3.2.2 errors, which give a request as such no code.
    /// </summary>
    [Theory]
    [InlineData("another-client")]
    [InlineData(null)]
    public async Task AnUpdateNamingAnotherClientId_IsInvalidClientMetadata(string? bodyClientId)
    {
        var update = new UpdateClientRequest(
            new ClientRequest { ClientId = ClientId },
            new ClientRegistrationRequest { ClientId = bodyClientId! });

        var result = await Validator(StoredSector).ValidateAsync(SingleIssuer.Tenant, update);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// The metadata is judged as an update of the very registration the request was authenticated against, the one
    /// the update is built from and written over, so a change the host makes to the client meanwhile cannot have the
    /// update judged under one security profile and stored under another.
    /// </summary>
    [Fact]
    public async Task AnUpdate_IsJudgedOnTheRegistrationItWasAuthenticatedAgainst()
    {
        ClientRegistrationValidationContext? judged = null;

        var result = await Validator(StoredSector, context => judged = context)
            .ValidateAsync(SingleIssuer.Tenant, Update());

        Assert.True(result.TryGetSuccess(out var valid));
        Assert.Equal(DynamicClientOperation.Update, judged?.Operation);
        Assert.Same(valid.Client.ClientInfo, judged?.StoredClient);
    }

    /// <summary>
    /// The update is built from the metadata as the pipeline leaves it, the values a step completes where the client
    /// named none included, not from the request as it arrived.
    /// </summary>
    [Fact]
    public async Task AnUpdate_CarriesTheMetadataAsThePipelineLeftIt()
    {
        var result = await Validator(
                StoredSector,
                context => context.Request = context.Request with { ClientName = "completed-by-the-pipeline" })
            .ValidateAsync(SingleIssuer.Tenant, Update());

        Assert.True(result.TryGetSuccess(out var valid));
        Assert.Equal("completed-by-the-pipeline", valid.RegistrationRequest.ClientName);
    }

    private static UpdateClientRequest Update()
        => new(new ClientRequest { ClientId = ClientId }, new ClientRegistrationRequest { ClientId = ClientId });

    private static UpdateClientRequestValidator Validator(
        string? derivedSector,
        Action<ClientRegistrationValidationContext>? onJudged = null)
    {
        var stored = new RegisteredClient(new ClientInfo(ClientId) { SectorIdentifier = StoredSector }, "token-id");

        var clientValidator = new Mock<IClientRequestValidator>();
        clientValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync((TenantDefinition _, ClientRequest request) => new ValidClientRequest(request, stored));

        var registrationValidator = new Mock<IClientRegistrationContextValidator>();
        registrationValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.IsAny<ClientRegistrationValidationContext>()))
            .Callback((TenantDefinition _, ClientRegistrationValidationContext context) =>
            {
                context.SectorIdentifier = derivedSector;
                onJudged?.Invoke(context);
            })
            .ReturnsAsync((OidcError?)null);

        return new UpdateClientRequestValidator(clientValidator.Object, registrationValidator.Object);
    }
}
