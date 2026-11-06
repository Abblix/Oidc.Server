// Abblix OIDC Client Library
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

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Client.Features.DeviceAuthorization;

/// <summary>
/// What the provider hands a device that has no browser of its own, per RFC 8628 section 3.2.
/// </summary>
/// <remarks>
/// Wire names are pinned with attributes rather than derived from a naming policy: the document comes from a
/// foreign provider, so reading it must not depend on how the host configures its serializer.
/// </remarks>
public sealed record DeviceAuthorizationResponse
{
    /// <summary>
    /// The device's own half of the exchange, presented at the token endpoint and never shown to anyone.
    /// </summary>
    [JsonPropertyName("device_code")]
    public required string DeviceCode { get; init; }

    /// <summary>
    /// The user's half: the short string the device displays and its user types at
    /// <see cref="VerificationUri"/>.
    /// </summary>
    [JsonPropertyName("user_code")]
    public required string UserCode { get; init; }

    /// <summary>
    /// Where the user is to go to authorize the device.
    /// </summary>
    [JsonPropertyName("verification_uri")]
    public required string VerificationUri { get; init; }

    /// <summary>
    /// The same address with the user code already in it, when the provider offers one.
    /// </summary>
    /// <remarks>
    /// RFC 8628 section 3.3.1 has this exist so a device can show the whole thing as a QR code or send it
    /// over NFC, sparing the user the typing. Optional, so a device that means to use it has to cope with
    /// its absence.
    /// </remarks>
    [JsonPropertyName("verification_uri_complete")]
    public string? VerificationUriComplete { get; init; }

    /// <summary>
    /// Seconds until this whole exchange expires.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }

    /// <summary>
    /// Seconds the client is to wait between polls, when the provider names a figure.
    /// </summary>
    /// <remarks>
    /// Absent means five, which RFC 8628 section 3.2 states as a MUST on the client rather than leaving to
    /// taste. Read it through <see cref="PollingInterval"/> rather than here, so that default is applied in
    /// one place.
    /// </remarks>
    [JsonPropertyName("interval")]
    public int? Interval { get; init; }

    /// <summary>
    /// How long this exchange has left.
    /// </summary>
    [JsonIgnore]
    public TimeSpan Lifetime => TimeSpan.FromSeconds(ExpiresIn);

    /// <summary>
    /// How long to wait between polls: what the provider asked for, or the five seconds RFC 8628 section 3.2
    /// requires when it asked for nothing.
    /// </summary>
    [JsonIgnore]
    public TimeSpan PollingInterval => TimeSpan.FromSeconds(Interval ?? DefaultPollingIntervalSeconds);

    /// <summary>
    /// The interval a client must assume when the provider names none (RFC 8628 section 3.2).
    /// </summary>
    private const int DefaultPollingIntervalSeconds = 5;

    /// <summary>
    /// Members of the response this client does not model, kept so a paid layer or a host can read a value
    /// the base client has no opinion about.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, object?>? AdditionalData { get; init; }
}
