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

using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

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

            // "not null and" is load-bearing since the null-mode exit moved below this switch: null is
            // "not (poll or ping or push)" as much as "carrier-pigeon" is, so without it a registration
            // naming no mode at all would be told its mode is unsupported.
            case {
                BackChannelTokenDeliveryMode: not null and not (
                    BackchannelTokenDeliveryModes.Poll or
                    BackchannelTokenDeliveryModes.Ping or
                    BackchannelTokenDeliveryModes.Push),
            }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "The specified token delivery mode is not supported");
        }

        // The VALUE, asked after the mode is settled and before a registration that names no mode can
        // leave. It used to sit inside the switch behind a first case returning for a null delivery
        // mode, so a registration naming the endpoint and no mode walked past unchecked and the
        // address was stored - measured, 201 Created over plain HTTP.
        // Nothing else covers the member: StoredUriValidator asks absoluteness only, and
        // SubjectTypeValidator's arm needs a pairwise subject type.
        //
        // Absoluteness first, because Scheme raises on a relative URI rather than returning anything:
        // a registration body carrying "/cb" here faulted the endpoint instead of being refused. The
        // [AbsoluteUri] on the member does not help - the form binder honours it and the JSON
        // deserializer does not - so each site that reads a URI member states absoluteness itself, and
        // a guard whose safety depends on another validator's position in a list moves when somebody
        // reorders that list.
        //
        // CIBA Core 1.0 Section 4, describing backchannel_client_notification_endpoint as registration
        // metadata: "It MUST be an HTTPS URL." That is the clause the check below enforces, and Section
        // 4 is where it is written for a registration request. Null passes, because a registration is
        // free not to name the endpoint at all; whether a mode REQUIRES one is the switch's question.
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
        // here, where the value is judged without reference to the mode. Both ARE implemented, by
        // SubjectTypeValidator in this same pipeline: it fetches the sector document and checks it for
        // whichever URI the registered mode names, and takes the sector from that same URI when the client
        // registered neither a sector_identifier_uri nor a redirect URI. Both absences, not one: a push
        // client that registered redirect URIs takes its sector from those, and this endpoint then plays no
        // part in the sector at all.
        //
        // The remaining Section 4 rule for this parameter, "REQUIRED if the token delivery mode is set
        // to ping or push", IS implemented - by the switch above, and the row driving each arm reads the
        // description rather than the code, so which of them answered is measured rather than asserted
        // here in prose.
        //
        // AFTER the arms above, so a registration that is wrong about the MODE hears about the mode
        // rather than about the scheme. Ordered the other way, a poll client naming a plain-HTTP
        // endpoint was told to use HTTPS, fixed the scheme, and was refused again because poll must
        // carry no endpoint at all - a correct refusal that leads nowhere.
        //
        // Still ahead of the null-mode exit below, which is what the first paragraph is about.
        //
        // invalid_client_metadata rather than invalid_request, because that is what a registration
        // refusal is and what the same member already gets from StoredUriValidator when it is relative.
        // One member answering with two codes told an integrator that two different kinds of thing had
        // gone wrong.
        if (context.Request.BackChannelClientNotificationEndpoint
            is not (null or { IsAbsoluteUri: true, Scheme: "https" }))
        {
            return new OidcError(
                ErrorCodes.InvalidClientMetadata,
                $"The {Parameters.BackChannelClientNotificationEndpoint} must be an absolute URI using "
                + "the HTTPS scheme");
        }

        if (context.Request.BackChannelTokenDeliveryMode is null)
            return null;

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
