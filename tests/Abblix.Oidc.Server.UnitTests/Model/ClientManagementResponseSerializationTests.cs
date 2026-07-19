// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Abblix.Oidc.Server.Model;
using Abblix.Utils.Json;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// Wire-shape regressions for the DCR / RFC 7592 client-management response DTOs:
/// #28 client_secret_expires_at must serialize as a Unix-seconds number (RFC 7591 §3.2.1), and
/// #31 unregistered metadata must be omitted rather than emitted as explicit null (RFC 7591/7592).
/// </summary>
public class ClientManagementResponseSerializationTests
{
    private static JsonSerializerOptions BuildOptions()
    {
        var options = new JsonSerializerOptions();
        options.TypeInfoResolverChain.Add(
            new DefaultJsonTypeInfoResolver { Modifiers = { JsonIgnoreNullsModifier.Apply } });
        return options;
    }

    [Fact]
    public void ReadClientSecretExpiresAt_SerializesAsUnixSecondsNumber()
    {
        // RFC 7591 §3.2.1 defines client_secret_expires_at as a number (seconds since epoch), matching
        // the register-path DTO. A fixed instant keeps the test off the ambient system clock.
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var response = new ReadClientSuccessfulResponse
        {
            ClientId = "client-1",
            RegistrationAccessToken = "registration-access-token",
            RedirectUris = [new Uri("https://client.example.com/cb")],
            ClientSecretExpiresAt = expiresAt,
        };

        var json = JsonSerializer.Serialize(response, BuildOptions());

        Assert.Contains("\"client_secret_expires_at\":1800000000", json);
        Assert.DoesNotContain("\"client_secret_expires_at\":\"", json);
    }

    [Fact]
    public void RegistrationResponse_NullableFieldsOmittedWhenNull()
    {
        // Minimal public-client registration: no secret, no optional metadata. RFC 7591 §3.2.1 models
        // unregistered metadata as absent members, not explicit nulls. System.Text.Json compact form
        // writes ":null" without spaces.
        var response = new ClientRegistrationResponse
        {
            ClientId = "client-1",
        };

        var json = JsonSerializer.Serialize(response, BuildOptions());

        Assert.DoesNotContain(":null", json);
    }

    [Fact]
    public void ReadResponse_NullableFieldsOmittedWhenNull()
    {
        var response = new ReadClientSuccessfulResponse
        {
            ClientId = "client-1",
            RegistrationAccessToken = "registration-access-token",
            RedirectUris = [new Uri("https://client.example.com/cb")],
        };

        var json = JsonSerializer.Serialize(response, BuildOptions());

        Assert.DoesNotContain(":null", json);
    }
}
