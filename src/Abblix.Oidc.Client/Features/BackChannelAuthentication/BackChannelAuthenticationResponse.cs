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

namespace Abblix.Oidc.Client.Features.BackChannelAuthentication;

/// <summary>
/// The provider's acknowledgement of a CIBA authentication request, per section 7.3.
/// </summary>
/// <remarks>
/// Wire names are pinned with attributes rather than derived from a naming policy: the document comes from a
/// foreign provider, so reading it must not depend on how the host configures its serializer.
/// </remarks>
public sealed record BackChannelAuthenticationResponse
{
    /// <summary>
    /// What identifies this request at the token endpoint afterwards.
    /// </summary>
    [JsonPropertyName("auth_req_id")]
    public required string AuthenticationRequestId { get; init; }

    /// <summary>
    /// Seconds until the request expires.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }

    /// <summary>
    /// Seconds to wait between polls, when the provider names a figure.
    /// </summary>
    /// <remarks>
    /// Read it through <see cref="PollingInterval"/> rather than here, so the fallback is applied in one
    /// place. CIBA section 7.3 leaves this OPTIONAL and section 11 has the client keep polling regardless, so
    /// a figure has to come from somewhere; five seconds is what RFC 8628 fixes for the same waiting, and
    /// this client applies it here too rather than inventing a second number.
    /// </remarks>
    [JsonPropertyName("interval")]
    public int? Interval { get; init; }

    /// <summary>
    /// How long this request has left.
    /// </summary>
    [JsonIgnore]
    public TimeSpan Lifetime => TimeSpan.FromSeconds(ExpiresIn);

    /// <summary>
    /// How long to wait between polls.
    /// </summary>
    [JsonIgnore]
    public TimeSpan PollingInterval => TimeSpan.FromSeconds(Interval ?? DefaultPollingIntervalSeconds);

    private const int DefaultPollingIntervalSeconds = 5;

    /// <summary>
    /// Members of the response this client does not model, kept so a paid layer or a host can read a value
    /// the base client has no opinion about.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, object?>? AdditionalData { get; init; }
}
