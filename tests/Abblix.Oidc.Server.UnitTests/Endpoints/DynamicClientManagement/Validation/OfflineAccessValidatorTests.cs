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
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A client registering itself asks for no offline access or for offline access with prompt=consent, and receives
/// the latter when it does not say; waiving prompt=consent is the host's statement about a client, so a client
/// asking for it is refused.
/// </summary>
public class OfflineAccessValidatorTests
{
    private readonly OfflineAccessValidator _validator = new();

    [Theory]
    [InlineData(OfflineAccess.Disabled, null)]
    [InlineData(OfflineAccess.ConsentRequired, null)]
    [InlineData(OfflineAccess.Allowed, ErrorCodes.InvalidClientMetadata)]
    public async Task ValidateAsync_RefusesOnlyOfflineAccessWithoutConsentPrompt(OfflineAccess offlineAccess, string? error)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            OfflineAccess = offlineAccess,
        });

        var result = await _validator.ValidateAsync(context);

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
