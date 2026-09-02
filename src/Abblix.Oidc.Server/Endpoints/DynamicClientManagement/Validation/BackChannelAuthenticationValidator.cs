// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates CIBA-related metadata (OpenID Connect Client-Initiated Backchannel Authentication 1.0, Section 4):
/// the consistency between <c>backchannel_token_delivery_mode</c> and
/// <c>backchannel_client_notification_endpoint</c>, and that
/// <c>backchannel_authentication_request_signing_alg</c> is on the server's supported list.
/// </summary>
/// <param name="jwtValidator">Source of supported JWT signing algorithms.</param>
public class BackChannelAuthenticationValidator(IJsonWebTokenValidator jwtValidator)
    : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Applies the CIBA consistency rules: <c>poll</c> must not include a notification endpoint;
    /// <c>ping</c> and <c>push</c> must include one; the signing algorithm, when present, must
    /// be supported.
    /// </summary>
    private OidcError? Validate(ClientRegistrationValidationContext context)
    {
        switch (context.Request)
        {
            case { BackChannelTokenDeliveryMode: null }:
                return null;

            case {
                BackChannelTokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
                BackChannelClientNotificationEndpoint: not null,
            }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "Notification endpoint is invalid if the token delivery mode is set to poll");

            case {
                BackChannelTokenDeliveryMode:
                    BackchannelTokenDeliveryModes.Ping or
                    BackchannelTokenDeliveryModes.Push,
                BackChannelClientNotificationEndpoint: null,
            }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "Notification endpoint is required if the token delivery mode is set to ping or push");

            case {
                BackChannelTokenDeliveryMode: not (
                    BackchannelTokenDeliveryModes.Poll or
                    BackchannelTokenDeliveryModes.Ping or
                    BackchannelTokenDeliveryModes.Push),
            }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "The specified token delivery mode is not supported");
        }

        // CIBA Core 1.0 Section 4, describing backchannel_client_notification_endpoint as registration
        // metadata: "It MUST be an HTTPS URL." That is the clause this line enforces, and Section 4 is
        // where it is written for a registration request.
        //
        // The TLS half is NOT in Section 4. It is Section 9, which restates the HTTPS rule and adds
        // "Communication with the Client Notification Endpoint MUST utilize TLS" - a property of the
        // transport a host establishes when it calls the endpoint, so nothing about the registered value
        // can decide it. PingModeValidator and PushModeValidator quote Section 9 and say the same of it.
        //
        // Section 4 carries two further rules about this parameter, and both belong to PUSH mode under
        // pairwise subject types: the endpoint "is used in place of the redirect_uri" as the sector
        // identifier, and where a sector_identifier_uri is registered the endpoint "must be included in
        // the list of URIs pointed to by" it. Poll and ping put the jwks_uri in both of those roles
        // instead, so neither rule reaches a ping registration - which is why they cannot be enforced
        // beside the HTTPS check, whose arm covers ping and push alike. Both ARE implemented, by
        // SubjectTypeValidator in this same pipeline: it fetches the sector document and checks it for
        // whichever URI the registered mode names, and takes the sector from that same URI when the client
        // registered neither a sector_identifier_uri nor a redirect URI. Both absences, not one: a push
        // client that registered redirect URIs takes its sector from those, and this endpoint then plays no
        // part in the sector at all.
        //
        // The remaining Section 4 rule for this parameter, "REQUIRED if the token delivery mode is set
        // to ping or push", IS implemented - by the switch above, in the words of the refusal it returns.
        //
        // A poll request carrying NO endpoint reaches this line: the switch rejects poll WITH one and
        // ping or push WITHOUT one, which leaves poll-with-nothing to fall through. That is what the null
        // check below is for.
        // Absoluteness first, because Scheme raises on a relative URI rather than returning anything:
        // a registration body carrying "/cb" here faulted the endpoint instead of being refused. The
        // [AbsoluteUri] on the member is honoured by the form binder and NOT by the JSON deserializer,
        // which is why StoredUriValidator reads the same attribute for the JSON route. That covers
        // absoluteness for every declared member; this line states it again because the arm below runs
        // before that validator and reads Scheme, which raises on a relative value. Only absoluteness is
        // shared - the scheme is per member, decided by the fetch policy where the server fetches and by
        // the specification where it redirects.
        var notificationEndpoint = context.Request.BackChannelClientNotificationEndpoint;
        if (notificationEndpoint is not (null or { IsAbsoluteUri: true, Scheme: "https" }))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The backchannel_client_notification_endpoint must be an absolute URI using the HTTPS scheme");
        }

        var signingAlgorithm = context.Request.BackChannelAuthenticationRequestSigningAlg;
        if (signingAlgorithm.HasValue() &&
            !jwtValidator.SigningAlgorithmsSupported.Contains(signingAlgorithm, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The specified signing algorithm is not supported");
        }

        return null;
    }
}
