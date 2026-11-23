// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Which addresses a client's metadata document may be fetched from, as
/// <see cref="ClientIdMetadataDocumentOptions.DocumentAddresses"/> sets it.
/// </summary>
/// <remarks>
/// Draft-ietf-oauth-client-id-metadata-document section 10.7: the server "MUST NOT fetch a Client ID Metadata Document
/// URL or any URLs contained within a Client ID Metadata Document that resolve to special-use IP addresses as defined
/// in [RFC6890]". Every member keeps that rule for the URLs a document contains; a member other than
/// <see cref="PublicOnly"/> relaxes it for the document's own URL alone.
/// </remarks>
[Experimental(ClientIdMetadataDocumentsExperiment.DiagnosticId, UrlFormat = ClientIdMetadataDocumentsExperiment.UrlFormat)]
public enum ClientIdMetadataDocumentAddresses
{
    /// <summary>
    /// No special-use address, loopback included: a document is fetched only from a public address.
    /// </summary>
    PublicOnly,

    /// <summary>
    /// A loopback address as well, and only for a tenant whose issuer is itself on a loopback address; a tenant with any
    /// other issuer is held to <see cref="PublicOnly"/>. So a provider and a client running on one development machine
    /// can try the feature.
    /// </summary>
    /// <remarks>
    /// Section 10.7 of the draft: "Authorization servers deployed for development or testing purposes MAY relax this
    /// restriction to allow fetching from loopback addresses when the authorization server itself is also running on a
    /// loopback address and the resolved address matches the same loopback interface. Authorization servers MUST NOT
    /// apply this exception in production deployments". So the exception is decided for each tenant at each lookup: it
    /// applies only where the tenant's issuer, as written, names <c>localhost</c>, an address of 127.0.0.0/8 or
    /// <c>::1</c>, and a client identifier naming a loopback host at any other tenant is refused with a warning that
    /// says why. A host whose environment is Production (<c>IHostEnvironment.IsProduction()</c>) does not start with this
    /// set, and fetches no document from loopback should the setting change after it started; one registering no
    /// <c>IHostEnvironment</c>, built without the generic host, is not taken for Production, and is held by the issuer
    /// rule alone. Nor does a host that sends outbound requests through
    /// <see cref="Features.SecureHttpFetch.SecureHttpFetchOptions.OutboundProxy"/>, which would reach the proxy's own
    /// loopback interface. A machine has one loopback interface, which carries all of these
    /// addresses, so a document is reached at any of them whichever one the issuer names.
    /// <para>
    /// The document's URL may then name <c>localhost</c> or a loopback literal, or a name resolving to loopback
    /// addresses alone; every other private or special-use address is still refused.
    /// <see cref="Features.SecureHttpFetch.SecureHttpFetchOptions.BlockPrivateNetworks"/> stays on, and
    /// <see cref="Features.SecureHttpFetch.SecureHttpFetchOptions.AllowedDestinations"/> still never admits a client
    /// identifier.
    /// </para>
    /// </remarks>
    AllowLoopback,
}
