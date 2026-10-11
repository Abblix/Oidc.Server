// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
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
        var result = await Validator(derivedSector).ValidateAsync(Update());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    [Fact]
    public async Task AnUpdateKeepingTheSector_IsAccepted()
    {
        var result = await Validator(StoredSector).ValidateAsync(Update());

        Assert.True(result.TryGetSuccess(out _));
    }

    private static UpdateClientRequest Update()
        => new(new ClientRequest { ClientId = ClientId }, new ClientRegistrationRequest { ClientId = ClientId });

    private static UpdateClientRequestValidator Validator(string? derivedSector)
    {
        var stored = new RegisteredClient(new ClientInfo(ClientId) { SectorIdentifier = StoredSector }, "token-id");

        var clientValidator = new Mock<IClientRequestValidator>();
        clientValidator
            .Setup(v => v.ValidateAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientRequest request) => new ValidClientRequest(request, stored));

        var registrationValidator = new Mock<IRegisterClientRequestValidator>();
        registrationValidator
            .Setup(v => v.ValidateAsync(It.IsAny<ClientRegistrationRequest>()))
            .ReturnsAsync((ClientRegistrationRequest request) => new ValidClientRegistrationRequest(request, derivedSector));

        return new UpdateClientRequestValidator(clientValidator.Object, registrationValidator.Object);
    }
}
