// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// The push error payload carries the three parameters CIBA Core 1.0 section 12 names, under those names.
/// </summary>
public class BackChannelPushErrorNotificationRequestTests
{
    private const string AuthReqId = "auth_req_1";

    /// <summary>
    /// Written as the sender writes it - by the payload's own type - the payload carries auth_req_id, error
    /// and error_description, and leaves error_description out when there is none, since it is optional.
    /// </summary>
    [Theory]
    [InlineData("The end user denied the authorization request")]
    [InlineData(null)]
    public void ThePayloadCarriesTheParametersSection12Names(string? description)
    {
        var payload = new BackChannelPushErrorNotificationRequest
        {
            AuthenticationRequestId = AuthReqId,
            Error = ErrorCodes.AccessDenied,
            ErrorDescription = description,
        };

        using var written = JsonDocument.Parse(JsonSerializer.Serialize(payload, payload.GetType()));
        var root = written.RootElement;

        // Literals on purpose: this test holds the member names as CIBA Core 1.0 section 12 spells them. Read through
        // BackChannelPushErrorNotificationRequest.Parameters, the same constants the payload is written with, the
        // test would compare a constant with itself, and changing one's value would break every client while this
        // stays green
        Assert.Equal(AuthReqId, root.GetProperty("auth_req_id").GetString());
        Assert.Equal(ErrorCodes.AccessDenied, root.GetProperty("error").GetString());
        Assert.Equal(
            description is not null,
            root.TryGetProperty("error_description", out var sent));

        if (description is not null)
            Assert.Equal(description, sent.GetString());
    }
}
