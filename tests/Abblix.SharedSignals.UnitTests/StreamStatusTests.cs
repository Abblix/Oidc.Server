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
/// Pins the status document shared by the read response and the update request
/// (SSF 1.0 Sections 8.1.2.1, 8.1.2.2).
/// </summary>
public class StreamStatusTests
{
    [Fact]
    public void Status_ReadsTheSpecificationFixture()
    {
        // The check-status response of SSF 1.0 Section 8.1.2.1, Figure 36, verbatim.
        var status = JsonSerializer.Deserialize<StreamStatus>(
            """
            {
                "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
                "status": "paused",
                "reason": "SYSTEM_DOWN_FOR_MAINTENANCE"
            }
            """);

        Assert.NotNull(status);
        Assert.Equal("f67e39a0a4d34d56b3aa1bc4cff0069f", status.StreamId);
        Assert.Equal(StreamStatuses.Paused, status.Status);
        Assert.Equal("SYSTEM_DOWN_FOR_MAINTENANCE", status.Reason);
    }

    [Fact]
    public void Status_WithoutTheOptionalReason_WritesTwoMembers()
    {
        // The update request of Figure 37 carries only the identifier and the new status; the
        // absent reason stays off the wire rather than traveling as null.
        var written = JsonNode.Parse(JsonSerializer.Serialize(new StreamStatus
        {
            StreamId = "f67e39a0a4d34d56b3aa1bc4cff0069f",
            Status = StreamStatuses.Paused,
        }))!.AsObject();

        Assert.Equal(2, written.Count);
        Assert.Equal(StreamStatuses.Paused, written[StreamMemberNames.Status]!.GetValue<string>());
    }

    [Fact]
    public void Status_MissingTheStatusMember_IsRefused()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<StreamStatus>(
            """{"stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f"}"""));
    }
}
