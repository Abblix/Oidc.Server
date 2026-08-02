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
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Validation;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the delivery DTOs to the wire documents RFC 8936 prints: each example body of
/// Section 2.4 round-trips through the typed model, absence stays absence, and the error-code
/// mapping covers every validation verdict.
/// </summary>
public class DeliveryContractTests
{
    private static void AssertSameJson(string expected, object value)
    {
        var actual = JsonSerializer.SerializeToNode(value);
        Assert.True(
            JsonNode.DeepEquals(JsonNode.Parse(expected), actual),
            $"Wire documents differ. Expected: {expected} Actual: {actual?.ToJsonString()}");
    }

    [Fact]
    public void DefaultPollRequest_IsTheEmptyObject()
    {
        // "A SET Recipient can poll using default parameter values by passing an empty JSON
        // object" (RFC 8936 Section 2.4.1, Figure 2): every absent member is OMITTED, not null.
        AssertSameJson("{}", new PollRequest());
    }

    [Fact]
    public void PollOnlyRequest_MatchesFigure1()
    {
        AssertSameJson(
            """{"returnImmediately": true}""",
            new PollRequest { ReturnImmediately = true });
    }

    [Fact]
    public void AcknowledgeOnlyRequest_MatchesFigure3()
    {
        AssertSameJson(
            """
            {
              "ack": [
                "4d3559ec67504aaba65d40b0363faad8",
                "3d0c3cf797584bd193bd0fb1bd4e7d30"
              ],
              "maxEvents": 0,
              "returnImmediately": true
            }
            """,
            new PollRequest
            {
                Acknowledged = ["4d3559ec67504aaba65d40b0363faad8", "3d0c3cf797584bd193bd0fb1bd4e7d30"],
                MaxEvents = 0,
                ReturnImmediately = true,
            });
    }

    [Fact]
    public void PollWithAcknowledgementAndErrors_MatchesFigure5()
    {
        AssertSameJson(
            """
            {
              "ack": ["3d0c3cf797584bd193bd0fb1bd4e7d30"],
              "setErrs": {
                "4d3559ec67504aaba65d40b0363faad8": {
                  "err": "authentication_failed",
                  "description": "The SET could not be authenticated"
                }
              },
              "returnImmediately": true
            }
            """,
            new PollRequest
            {
                Acknowledged = ["3d0c3cf797584bd193bd0fb1bd4e7d30"],
                Errors = new Dictionary<string, DeliveryError>
                {
                    ["4d3559ec67504aaba65d40b0363faad8"] = new(
                        DeliveryErrorCodes.AuthenticationFailed,
                        "The SET could not be authenticated"),
                },
                ReturnImmediately = true,
            });
    }

    [Fact]
    public void EmptyPollResponse_MatchesFigure7()
    {
        // "If there are no outstanding SETs to be transmitted, the JSON object SHALL be empty"
        // (RFC 8936 Section 2.3): "sets" is present and empty, never absent.
        AssertSameJson("""{"sets": {}}""", new PollResponse());
    }

    [Fact]
    public void PollResponse_RoundTripsThroughTheModel()
    {
        var json =
            """
            {
              "sets": { "jti-1": "h.p.s", "jti-2": "h2.p2.s2" },
              "moreAvailable": true
            }
            """;

        var response = JsonSerializer.Deserialize<PollResponse>(json);

        Assert.NotNull(response);
        Assert.Equal(2, response.Sets.Count);
        Assert.Equal("h.p.s", response.Sets["jti-1"]);
        Assert.True(response.MoreAvailable);
        AssertSameJson(json, response);
    }

    [Fact]
    public void PushFailureBody_MatchesTheFigure3ShapeOfRfc8935()
    {
        AssertSameJson(
            """
            {
              "err": "invalid_key",
              "description": "Key ID 12345 has been revoked."
            }
            """,
            new DeliveryError(DeliveryErrorCodes.InvalidKey, "Key ID 12345 has been revoked."));
    }

    [Fact]
    public void EveryValidationVerdict_MapsToARegisteredDeliveryCode()
    {
        // The mapping's default arm throws for an unmapped verdict; walking every enum value is
        // what turns "a new verdict was added without extending the table" into a red test
        // instead of a runtime surprise.
        var registered = new[]
        {
            DeliveryErrorCodes.InvalidRequest,
            DeliveryErrorCodes.InvalidKey,
            DeliveryErrorCodes.InvalidIssuer,
            DeliveryErrorCodes.InvalidAudience,
            DeliveryErrorCodes.AuthenticationFailed,
            DeliveryErrorCodes.AccessDenied,
        };

        foreach (var code in Enum.GetValues<SecurityEventTokenErrorCode>())
        {
            Assert.Contains(DeliveryErrorCodes.FromValidationError(code), registered);
        }
    }

    [Fact]
    public void TransportVerdicts_AreNotProducedByTheTokenPipeline()
    {
        // authentication_failed and access_denied judge the transmitter, not the token, so no
        // validation verdict may map to them - a pipeline that produced them would be claiming
        // knowledge of a transport it never sees.
        var transportOnly = new[] { DeliveryErrorCodes.AuthenticationFailed, DeliveryErrorCodes.AccessDenied };

        foreach (var code in Enum.GetValues<SecurityEventTokenErrorCode>())
        {
            Assert.DoesNotContain(DeliveryErrorCodes.FromValidationError(code), transportOnly);
        }
    }
}
