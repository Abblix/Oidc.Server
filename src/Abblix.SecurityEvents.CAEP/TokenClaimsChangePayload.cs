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

using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// Token Claims Change (CAEP 1.0 Section 3.2): a claim in the token identified by the subject -
/// a JWT through the jwt_id subject format, a SAML assertion through saml_assertion_id - has
/// changed. When <see cref="CaepEventPayload.EventTimestamp"/> is included it is the moment the
/// claim values changed.
/// </summary>
public sealed record TokenClaimsChangePayload : CaepEventPayload
{
    /// <summary>
    /// REQUIRED. The changed claims with their new values (CAEP 1.0 Section 3.2.1). Raw JSON,
    /// because the claims are whatever the token carries - OIDC names or SAML claim URIs alike.
    /// </summary>
    [JsonPropertyName(CaepClaimNames.Claims)]
    public required JsonObject Claims { get; init; }
}
