// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the add- and remove-subject request bodies (SSF 1.0 Sections 8.1.3.2, 8.1.3.3),
/// including that the subject member rides the RFC 9493 polymorphic dispatch.
/// </summary>
public class StreamSubjectRequestTests
{
    [Fact]
    public void AddSubject_ReadsTheSpecificationFixture()
    {
        // The add-subject request of SSF 1.0 Section 8.1.3.2, Figure 40, verbatim.
        var request = JsonSerializer.Deserialize<AddSubjectRequest>(
            """
            {
                "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
                "subject": {
                    "format": "email",
                    "email": "example.user@example.com"
                },
                "verified": true
            }
            """);

        Assert.NotNull(request);
        Assert.Equal("f67e39a0a4d34d56b3aa1bc4cff0069f", request.StreamId);
        var email = Assert.IsType<EmailSubject>(request.Subject);
        Assert.Equal("example.user@example.com", email.Email);
        Assert.True(request.Verified);
    }

    [Fact]
    public void AddSubject_OmittedVerified_StaysOffTheWire()
    {
        // "If omitted, Event Transmitters SHOULD assume that the subject has been verified"
        // (SSF 1.0 Section 8.1.3.2) - so the absence is itself the common, meaningful form.
        var written = JsonNode.Parse(JsonSerializer.Serialize(new AddSubjectRequest
        {
            StreamId = "stream-1",
            Subject = new EmailSubject("example.user@example.com"),
        }))!.AsObject();

        Assert.False(written.ContainsKey(StreamMemberNames.Verified));
        Assert.Equal(2, written.Count);
    }

    [Fact]
    public void RemoveSubject_RoundTripsWithThePhoneNumberFormat()
    {
        // Figure 42's remove-subject example, with one correction: the figure writes
        // "format": "phone", but RFC 9493 Section 3.2.5 registers the format as
        // "phone_number" - the registry wins over the specification's own example.
        var request = JsonSerializer.Deserialize<RemoveSubjectRequest>(
            """
            {
                "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
                "subject": {
                    "format": "phone_number",
                    "phone_number": "+12065550123"
                }
            }
            """);

        Assert.NotNull(request);
        var phone = Assert.IsType<PhoneNumberSubject>(request.Subject);
        Assert.Equal("+12065550123", phone.PhoneNumber);

        var written = JsonNode.Parse(JsonSerializer.Serialize(request))!.AsObject();
        Assert.Equal(
            SubjectFormats.PhoneNumber,
            written[StreamMemberNames.Subject]![SubjectMemberNames.Format]!.GetValue<string>());
    }

    [Fact]
    public void AddSubject_MissingTheSubject_IsRefused()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<AddSubjectRequest>(
            """{"stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f"}"""));
    }
}
