// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Judges the audience of a client authentication assertion against what its client may name there.
/// </summary>
/// <param name="logger">Records which form of audience was accepted, or why none was.</param>
/// <param name="serviceProvider">Resolves, per request, where the transport serves the endpoints a client may be
/// allowed to name.</param>
internal sealed partial class ClientAssertionAudience(ILogger logger, IServiceProvider serviceProvider)
{
    /// <summary>
    /// Answers whether the assertion names an audience of <see cref="ClientInfo.ClientAssertionAudiences"/> in a form
    /// the set admits: this tenant's issuer identifier, or, for a client granted
    /// <see cref="ClientAssertionAudiences.TokenEndpoint"/>, the token endpoint URL or its mutual-TLS alias, for one
    /// granted <see cref="ClientAssertionAudiences.BackChannelAuthenticationEndpoint"/>, the backchannel authentication
    /// endpoint URL or its alias, for one granted
    /// <see cref="ClientAssertionAudiences.PushedAuthorizationRequestEndpoint"/>, the pushed authorization request
    /// endpoint URL or its alias, each as a string, or in an array of strings beside others for a client granted
    /// <see cref="ClientAssertionAudiences.AllowArray"/>.
    /// </summary>
    /// <remarks>
    /// RFC 10070 section 4 (case B, client authentication): the authorization server "MUST reject any JWT that
    /// does not contain its issuer identifier as its sole audience value", and "the token endpoint URL of the
    /// authorization server MUST NOT be used as an audience value". Section 5 says the same of an assertion at
    /// the pushed authorization request endpoint, and section 7 refers to [private_key_jwt.Disclosure] and
    /// [Audience.Injection] for the attacks this closes: an audience other than the issuer, or one beside it,
    /// would let an assertion a client minted for another server be presented here. The claim is
    /// read as written rather than through the typed accessor, which skips members that are not strings and
    /// would read the issuer beside one as the sole value. Compared by RFC 3986 section 6.2.1, as section 4
    /// prescribes. A profile may narrow the set: FAPI 2.0 section 5.3.2.1 takes the issuer identifier alone, so
    /// under such a profile the endpoint URLs and an array are refused whatever the client was granted, and
    /// the client is refused here before its jti is spent, whatever order the authenticators run in.
    /// </remarks>
    public bool IsAccepted(TenantDefinition tenant, JsonWebToken token, ClientInfo clientInfo)
    {
        // What the client may name once its profile has narrowed the set, so the refusal logs what was applied
        var audiences = clientInfo.ClientAssertionAudiences.AdmittedBy(
            SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile));
        var allowArray = audiences.HasFlag(ClientAssertionAudiences.AllowArray);

        var audience = token.Payload.Json[JwtClaimTypes.Audience];
        if (audiences.HasFlag(ClientAssertionAudiences.Issuer) &&
            AudienceClaim.Names(audience, allowArray, tenant.IssuerIsNamedBy))
        {
            return true;
        }

        if (NamesGrantedEndpoint(
                tenant, audience, audiences, ClientAssertionAudiences.TokenEndpoint, OidcEndpoints.Token))
        {
            LogTokenEndpointAudienceAccepted(clientInfo.ClientId);
            return true;
        }

        if (NamesGrantedEndpoint(
                tenant,
                audience,
                audiences,
                ClientAssertionAudiences.BackChannelAuthenticationEndpoint,
                OidcEndpoints.BackChannelAuthentication))
        {
            LogBackChannelAuthenticationEndpointAudienceAccepted(clientInfo.ClientId);
            return true;
        }

        if (NamesGrantedEndpoint(
                tenant,
                audience,
                audiences,
                ClientAssertionAudiences.PushedAuthorizationRequestEndpoint,
                OidcEndpoints.PushedAuthorizationRequest))
        {
            LogPushedAuthorizationRequestEndpointAudienceAccepted(clientInfo.ClientId);
            return true;
        }

        // Logged from the claim itself: the typed accessor skips members that are not strings, so for the issuer
        // beside such a member it would log the issuer alone next to the refusal
        LogAudienceIsNotOneTheClientMayName(
            clientInfo.ClientId, Sanitized.Value(audience?.ToJsonString()), audiences, tenant.IssuerAsWritten());
        return false;
    }

    /// <summary>
    /// Answers whether <paramref name="audiences"/> hold <paramref name="grant"/> and the audience claim names a
    /// spelling of <paramref name="endpoint"/>, as a string or, when the set allows one, in an array.
    /// </summary>
    /// <remarks>
    /// The spellings are resolved only once the grant is found, since they take a scope of their own, which a client
    /// naming the issuer never needs.
    /// </remarks>
    private bool NamesGrantedEndpoint(
        TenantDefinition tenant,
        JsonNode? audience,
        ClientAssertionAudiences audiences,
        ClientAssertionAudiences grant,
        OidcEndpoints endpoint)
    {
        if (!audiences.HasFlag(grant))
            return false;

        var spellings = tenant.AcceptedSpellings(serviceProvider, endpoint);
        return AudienceClaim.Names(
            audience,
            audiences.HasFlag(ClientAssertionAudiences.AllowArray),
            written => spellings.Contains(written, StringComparer.Ordinal));
    }
}
