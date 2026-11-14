// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// Defines the interface for fetching and processing JWT request objects, validating their content
/// and binding their payloads to a request model.
/// This is typically used in OpenID Connect flows where request parameters are passed as JWTs.
/// </summary>
public interface IRequestObjectFetcher
{
    /// <summary>
    /// Fetches and processes the request object by validating its JWT and binding the payload to the request model.
    /// </summary>
    /// <typeparam name="T">The type of the request model.</typeparam>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="client">The client the request names outside the object, whose profile the object is held to
    /// before it is read; null where it names none.</param>
    /// <param name="request">The initial request model to bind the JWT payload to.</param>
    /// <param name="requestObject">The JWT contained within the request, if any.</param>
    /// <param name="requiredSigningAlgorithm">Optional selector returning the algorithm the resolved
    /// client registered for this kind of request object (e.g. <c>request_object_signing_alg</c> for
    /// authorization requests or <c>backchannel_authentication_request_signing_alg</c> for CIBA). When
    /// it returns a non-empty value, a request object whose <c>alg</c> differs is rejected.</param>
    /// <param name="forbiddenMembers">Parameters the request object must not include, such as <c>request</c> and
    /// <c>request_uri</c> for an authorization request (RFC 9101 section 4). An object carrying any of them, whatever
    /// its value, is refused with <c>invalid_request_object</c> before its parameters are used; empty where the
    /// request kind forbids none.</param>
    /// <param name="whyRefused">The request kind's own rule on the validated claims, such as the registered claims a
    /// signed CIBA authentication request must carry: why it refuses them, refused with <c>invalid_request_object</c>,
    /// or null where it accepts them.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result{T, AuthError}"/> object,
    /// which either represents a successfully processed request or an error indicating issues with the JWT validation.
    /// </returns>
    /// <remarks>
    /// This method is responsible for decoding and validating the JWT contained in the request. If the JWT is valid,
    /// the payload is bound to the request model.
    /// If the JWT is invalid or not present, an appropriate error result is returned.
    /// </remarks>
    Task<Result<T, OidcError>> FetchAsync<T>(
        TenantDefinition tenant,
        ClientInfo? client,
        T request,
        string? requestObject,
        Func<ClientInfo, string?>? requiredSigningAlgorithm,
        string[] forbiddenMembers,
        Func<JsonObject, string?> whyRefused)
        where T : class;
}
