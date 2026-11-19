// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// The SSRF validation of the transport a client's metadata document is fetched on, refusing every block of the
/// special-purpose address registries as written.
/// </summary>
/// <remarks>
/// Draft-ietf-oauth-client-id-metadata-document section 10.7: the server "MUST NOT fetch a Client ID Metadata Document
/// URL ... that resolve[s] to special-use IP addresses as defined in [RFC6890]". The shared validation lets the NAT64
/// prefix through to the public IPv4 address it carries, which an IPv6-only network needs for its other fetches; this
/// one refuses it.
/// </remarks>
/// <param name="options">The deployment's outbound fetch settings.</param>
/// <param name="uriValidator">Applies the synchronous scheme, hostname and IP-literal rules.</param>
/// <param name="resolveHost">Resolves a hostname to its addresses, the system's resolution unless a test names another.
/// </param>
internal sealed class ClientIdMetadataDocumentGuard(
    IOptions<SecureHttpFetchOptions> options,
    ISecureUriValidator uriValidator,
    ResolveHostDelegate? resolveHost = null) : SsrfValidatingHttpMessageHandler(options, uriValidator, resolveHost)
{
    /// <inheritdoc />
    protected override bool IsRefusedAddress(IPAddress address) => PrivateNetworks.IsSpecialPurposeAddress(address);
}
