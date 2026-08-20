// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
