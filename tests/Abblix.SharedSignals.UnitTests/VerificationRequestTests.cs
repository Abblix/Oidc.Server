// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SharedSignals.Model;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the trigger-verification request body (SSF 1.0 Section 8.1.4.2).
/// </summary>
public class VerificationRequestTests
{
    [Fact]
    public void Verification_ReadsTheSpecificationFixture()
    {
        // The trigger-verification request of SSF 1.0 Section 8.1.4.2, Figure 44, verbatim.
        var request = JsonSerializer.Deserialize<VerificationRequest>(
            """
            {
                "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
                "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="
            }
            """);

        Assert.NotNull(request);
        Assert.Equal("f67e39a0a4d34d56b3aa1bc4cff0069f", request.StreamId);
        Assert.Equal("VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=", request.State);
    }

    [Fact]
    public void Verification_WithoutState_WritesTheIdentifierAlone()
    {
        // The state is the receiver's correlation handle and is optional; absent, it stays off
        // the wire entirely (SSF 1.0 Section 8.1.4.2).
        var written = JsonNode.Parse(JsonSerializer.Serialize(new VerificationRequest
        {
            StreamId = "f67e39a0a4d34d56b3aa1bc4cff0069f",
        }))!.AsObject();

        var member = Assert.Single(written);
        Assert.Equal(StreamMemberNames.StreamId, member.Key);
    }

    [Fact]
    public void Verification_MissingTheStreamId_IsRefused()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<VerificationRequest>(
            """{"state": "opaque"}"""));
    }
}
