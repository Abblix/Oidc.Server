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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// A push mode client whose registration cannot carry the flow has authenticated, so it is refused with
/// unauthorized_client (CIBA Core 1.0 section 13, "The Client is not authorized to use this authentication flow"),
/// never with invalid_client, whose 401 would challenge credentials that worked.
/// </summary>
public class PushModeValidatorTests
{
    private readonly PushModeValidator _validator = new();

    [Theory]
    [InlineData(null)]
    [InlineData("http://client.example.com/ciba/notify")]
    public async Task A_push_client_without_an_https_notification_endpoint_is_unauthorized_client(string? endpoint)
    {
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest(),
            new ClientRequest())
        {
            ClientInfo = new ClientInfo("ciba_client_123")
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
                BackChannelClientNotificationEndpoint = endpoint is null ? null : new Uri(endpoint),
            },
        };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(ErrorCodes.UnauthorizedClient, Assert.IsType<OidcError>(result).Error);
    }

    [Fact]
    public async Task A_push_client_with_an_https_notification_endpoint_passes()
    {
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest(),
            new ClientRequest())
        {
            ClientInfo = new ClientInfo("ciba_client_123")
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
                BackChannelClientNotificationEndpoint = new Uri("https://client.example.com/ciba/notify"),
            },
        };

        Assert.Null(await _validator.ValidateAsync(SingleIssuer.Tenant, context));
    }
}
