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

using Abblix.Utils;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Fetches pushed authorization request objects identified by a URN (Uniform Resource Name) from a storage system.
/// </summary>
/// <param name="options">
/// Provides configuration options for the OIDC server, such as whether PAR is required.</param>
/// <param name="authorizationRequestStorage">
/// The storage system used to retrieve pushed authorization request objects.</param>
/// <param name="clientInfoProvider">
/// Resolves the requesting client's registration to enforce the per-client PAR requirement.</param>
public class PushedRequestFetcher(
    IOptionsSnapshot<OidcOptions> options,
    IAuthorizationRequestStorage authorizationRequestStorage,
    IClientInfoProvider clientInfoProvider) : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Asynchronously retrieves the pushed authorization request object associated with the specified URN.
    /// </summary>
    /// <param name="request">
    /// The authorization request containing a URN from which to fetch the stored pushed authorization request object.
    /// </param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains the fetched pushed authorization
    /// request object or an error if not found.
    /// </returns>
    /// <remarks>
    /// This method checks if the provided authorization request contains a URN that references a pushed authorization
    /// request stored in the system. If the URN is valid and corresponds to a stored request, the method retrieves
    /// and returns the request object. If the request object cannot be found or the URN is invalid,
    /// an error is returned.
    /// Additionally, it checks the server configuration to enforce the Pushed Authorization Request (PAR) requirement.
    /// </remarks>
    public async Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(AuthorizationRequest request)
    {
        // If the request contains a URN, attempt to retrieve the pushed authorization request from storage
        if (request is { RequestUri: { } requestUrn } &&
            requestUrn.OriginalString.StartsWith(RequestUrn.Prefix))
        {
            // Do not consume the request_uri here. RFC 9126 §7.3 says request_uri SHOULD be
            // one-time-use, and the natural moment to consume is at authorization-code
            // issuance - not at the first /authorize fetch. Consuming on fetch makes any
            // multi-step UI flow brittle: page refresh during login, back-button after
            // ConsentRequired, or the OIDF Conformance Suite's reuse-protection probes all
            // produce a spurious "Can't find a request by urn:..." instead of the expected
            // continuation. Single-use is still enforced - by the cache TTL upper bound and,
            // when the flow completes, by PushedAuthorizationRequestProcessorDecorator, which
            // consumes the request_uri carried forward below once a code or token is issued.
            var requestObject = await authorizationRequestStorage.TryGetAsync(requestUrn, shouldRemove: false);
            return requestObject switch
            {
                null => ErrorFactory.InvalidRequestUri($"Can't find a request by {requestUrn}"),

                // Carry the URN forward on a dedicated, non-wire field - not RequestUri, whose https
                // validation a urn: value would fail in the next fetcher - so the validator can surface it
                // on ValidAuthorizationRequest and the single-use decorator can consume it at code issuance.
                _ => requestObject with { PushedRequestUri = requestUrn },
            };
        }

        // If PAR is required by server configuration, return an error if no pushed authorization request is provided
        if (options.Value.RequirePushedAuthorizationRequests)
        {
            return ErrorFactory.InvalidRequestObject("The Pushed Authorization Request (PAR) is required");
        }

        // RFC 9126 §6: the per-client require_pushed_authorization_requests metadata makes PAR the
        // only way for this client to start an authorization flow, independent of the server-wide
        // flag. A code-only/high-assurance profile (FAPI 2.0) imposes the same requirement on the
        // client even when neither the server-wide flag nor the per-client metadata is set - the
        // profile tightens and the granular toggle cannot weaken it. Enforced here (not in the shared
        // context-validator pipeline) because this fetcher participates only in the authorization
        // endpoint's chain - the PAR endpoint itself runs a different fetcher set and must not trip
        // over the requirement it is there to satisfy.
        if (request.ClientId is { } clientId &&
            await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck() is { } clientInfo &&
            (clientInfo.RequirePushedAuthorizationRequests ||
             SecurityProfileRequirements.For(clientInfo, options.Value.DefaultSecurityProfile)
                 .RequirePushedAuthorizationRequests))
        {
            return ErrorFactory.InvalidRequestObject(
                "The client is required to use Pushed Authorization Requests (PAR)");
        }

        // If no URN is provided and PAR is not required, return the original request
        return request;
    }
}
