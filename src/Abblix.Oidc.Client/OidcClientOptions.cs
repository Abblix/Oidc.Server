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

namespace Abblix.Oidc.Client;

/// <summary>
/// Configuration for the Abblix OIDC/OAuth client.
/// </summary>
/// <remarks>
/// Holds what the client is, not who it talks to. Where the provider's endpoints come from is configured with
/// the metadata source the host registers, so a client that discovers its provider and one that is told its
/// endpoints do not share a settings surface neither of them fully uses.
/// </remarks>
public sealed class OidcClientOptions
{
    /// <summary>
    /// The client identifier issued by the OpenID Provider, sent as the <c>client_id</c> parameter.
    /// </summary>
    public required string ClientId { get; set; }
}
