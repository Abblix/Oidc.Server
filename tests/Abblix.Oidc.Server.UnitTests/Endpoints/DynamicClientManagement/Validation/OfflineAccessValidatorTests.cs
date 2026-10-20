// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A client registering itself asks for no offline access or for offline access with prompt=consent, and receives
/// the latter when it does not say; waiving prompt=consent is the host's statement about a client, so a client
/// asking for it is refused, unless it updates its registration and the host has already allowed it.
/// </summary>
public class OfflineAccessValidatorTests
{
    private const string ClientId = "registered-client";

    private static OfflineAccessValidator Validator(OfflineAccess? existing)
    {
        var clients = new Mock<IClientInfoProvider>();
        clients
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(existing is { } offlineAccess ? new ClientInfo(ClientId) { OfflineAccess = offlineAccess } : null);
        return new OfflineAccessValidator(clients.Object);
    }

    private static ClientRegistrationValidationContext Context(
        OfflineAccess offlineAccess,
        DynamicClientOperation operation = DynamicClientOperation.Register)
        => new(new ClientRegistrationRequest
        {
            ClientId = ClientId,
            RedirectUris = [TestConstants.DefaultRedirectUri],
            OfflineAccess = offlineAccess,
        })
        {
            Operation = operation,
        };

    [Theory]
    [InlineData(OfflineAccess.Disabled, null)]
    [InlineData(OfflineAccess.ConsentRequired, null)]
    [InlineData(OfflineAccess.Allowed, ErrorCodes.InvalidClientMetadata)]
    [InlineData((OfflineAccess)7, ErrorCodes.InvalidClientMetadata)]
    public async Task ARegistration_IsRefusedOfflineAccessWithoutConsentPromptOrAnUnnamedValue(
        OfflineAccess offlineAccess, string? error)
    {
        var result = await Validator(existing: null).ValidateAsync(Context(offlineAccess));

        Assert.Equal(error, result?.Error);
    }

    /// <summary>
    /// RFC 7592 section 2.2 has an update carry the metadata as the server returned it, so a client the host allowed
    /// sends allowed back and keeps it, while a client the host did not allow cannot raise itself to it.
    /// </summary>
    [Theory]
    [InlineData(OfflineAccess.Allowed, null)]
    [InlineData(OfflineAccess.ConsentRequired, ErrorCodes.InvalidClientMetadata)]
    [InlineData(OfflineAccess.Disabled, ErrorCodes.InvalidClientMetadata)]
    public async Task AnUpdate_KeepsAllowedOnlyForAClientAlreadyAllowed(OfflineAccess existing, string? error)
    {
        var result = await Validator(existing).ValidateAsync(Context(OfflineAccess.Allowed, DynamicClientOperation.Update));

        Assert.Equal(error, result?.Error);
    }

    /// <summary>
    /// The parameter carries each value under its registration name, and a request that does not state it asks for
    /// offline access with prompt=consent.
    /// </summary>
    [Theory]
    [InlineData("disabled", OfflineAccess.Disabled)]
    [InlineData("consent_required", OfflineAccess.ConsentRequired)]
    [InlineData("allowed", OfflineAccess.Allowed)]
    [InlineData(null, OfflineAccess.ConsentRequired)]
    public void OfflineAccess_IsReadByItsRegistrationName(string? name, OfflineAccess expected)
        => Assert.Equal(expected, Read(name)?.OfflineAccess);

    [Fact]
    public void OfflineAccess_OfAnUnknownName_IsNotRead()
        => Assert.Throws<JsonException>(() => Read("always"));

    private static ClientRegistrationRequest? Read(string? offlineAccess)
    {
        var json = new JsonObject();
        if (offlineAccess != null)
            json[ClientRegistrationRequest.Parameters.OfflineAccess] = offlineAccess;

        return json.Deserialize<ClientRegistrationRequest>();
    }
}
