// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Defaults used by the dynamic client registration endpoint when minting credentials for a newly
/// registered client: how its client identifier and client secret are generated and how long the
/// secret stays valid.
/// </summary>
public record NewClientOptions
{
    /// <summary>
    /// Generation parameters for the client identifier issued to a newly registered client.
    /// </summary>
    public ClientIdOptions ClientId { get; init; } = new();

    /// <summary>
    /// Generation parameters and lifetime policy for the client secret issued to a newly registered client.
    /// </summary>
    public ClientSecretOptions ClientSecret { get; init; } = new();

    /// <summary>
    /// The scope values a client registering without a <c>scope</c> member may request: the default set
    /// RFC 7591 section 2 lets the server register such a client with. Unset, the client may request any scope.
    /// </summary>
    /// <remarks>
    /// Applied on registration and on every RFC 7592 update that omits the member, since an update replaces the
    /// metadata whole.
    /// </remarks>
    public string[]? Scope { get; init; }

    /// <summary>
    /// The resources a dynamically registered client may get an access token for: the list a client registering
    /// without an <c>allowed_resources</c> member is given, and the set a list it sends has to stay within. Unset, a
    /// client registering without the member may get a token for any registered resource, and one sending a resource
    /// is refused, since which resources a client reaches is the server's policy rather than the client's choice.
    /// </summary>
    /// <remarks>
    /// Applied on registration and on every RFC 7592 update, since an update replaces the metadata whole.
    /// </remarks>
    public Uri[]? AllowedResources { get; init; }

    /// <summary>
    /// The token exchange audiences a dynamically registered client may name: the list a client registering without
    /// a <c>token_exchange_audiences</c> member is given, and the set a list it sends has to stay within. Unset, a
    /// client registering without the member may name no audience, and one sending an audience is refused.
    /// </summary>
    /// <remarks>
    /// Applied on registration and on every RFC 7592 update, since an update replaces the metadata whole.
    /// </remarks>
    public string[]? TokenExchangeAudiences { get; init; }
}
