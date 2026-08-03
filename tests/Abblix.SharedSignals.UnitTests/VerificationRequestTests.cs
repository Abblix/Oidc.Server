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
