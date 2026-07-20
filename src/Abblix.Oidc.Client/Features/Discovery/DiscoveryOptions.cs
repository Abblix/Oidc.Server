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

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// Configuration for reading the provider's discovery document.
/// </summary>
/// <remarks>
/// Separate from <see cref="OidcClientOptions"/> because these settings only mean anything to a client that
/// discovers its provider. A client configured against a provider that publishes no document never sees them.
/// </remarks>
public sealed class DiscoveryOptions
{
    /// <summary>
    /// The base address of the OpenID Provider. The discovery document is read from the well-known path under
    /// this address, and the issuer the provider declares is checked against it.
    /// </summary>
    public Uri? Authority { get; set; }

    /// <summary>
    /// The exact address of the discovery document, for a provider that publishes it somewhere other than
    /// under <see cref="Authority"/>. Leave unset to use the well-known path, which is the normal case.
    /// </summary>
    public Uri? MetadataAddress { get; set; }

    /// <summary>
    /// How long a fetched discovery document is reused before it is read again.
    /// </summary>
    /// <remarks>
    /// The document changes rarely, but it carries the provider's key set location and endpoints, so the
    /// lifetime bounds how long the client keeps following a provider that has moved. Twelve hours refreshes
    /// twice a day without making discovery a per-request cost.
    /// </remarks>
    public TimeSpan MetadataCacheLifetime { get; set; } = TimeSpan.FromHours(12);
}
