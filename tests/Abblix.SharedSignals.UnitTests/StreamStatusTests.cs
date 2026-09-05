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
