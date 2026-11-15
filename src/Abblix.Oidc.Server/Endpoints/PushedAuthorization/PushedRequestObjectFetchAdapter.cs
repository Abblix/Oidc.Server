// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RequestObject;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization;

/// <summary>
/// Reads the request object of a pushed authorization request as the authorization endpoint does, except that every
/// object must name its client.
/// </summary>
/// <param name="requestObjectFetcher">The request object fetcher responsible for fetching and processing
/// the JWT request object.</param>
/// <param name="clientInfoProvider">Finds the client the request names outside the object.</param>
public class PushedRequestObjectFetchAdapter(
    IRequestObjectFetcher requestObjectFetcher,
    IClientInfoProvider clientInfoProvider) : RequestObjectFetchAdapter(requestObjectFetcher, clientInfoProvider)
{
    /// <summary>
    /// RFC 9126 section 3 step 3: "reject the request if the authenticated "client_id" does not match the "client_id"
    /// claim in the Request Object", and the same section has "The rules for processing, signing, and encryption of
    /// the Request Object as defined in JAR [RFC9101] apply", so an unsecured object is held to it too.
    /// </summary>
    /// <param name="requestObject">The validated request object.</param>
    protected override string? WhyRefused(JsonWebToken requestObject)
        => NamesNoClient(requestObject) ? NoClientNamed : null;
}
