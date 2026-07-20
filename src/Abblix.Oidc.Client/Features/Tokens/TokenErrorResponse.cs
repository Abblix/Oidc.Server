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


using System.Text.Json.Serialization;

namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// What the token endpoint returns on failure, per RFC 6749 section 5.2.
/// </summary>
public sealed record TokenErrorResponse
{
    /// <summary>
    /// The machine-readable reason the request was refused.
    /// </summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }

    /// <summary>
    /// A human-readable elaboration, when the provider offers one.
    /// </summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; init; }
}
