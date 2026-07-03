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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the algorithms a client commits to using on inbound JWTs the server will verify:
/// <c>request_object_signing_alg</c> (OIDC Core §6.1),
/// <c>backchannel_authentication_request_signing_alg</c> (CIBA §7.1.1), and
/// <c>token_endpoint_auth_signing_alg</c> (RFC 7591 §2 / RFC 8414 §2). Each must appear in the
/// matching set the server advertises in discovery: <c>request_object_signing_alg</c> may be
/// <c>none</c>, but <c>token_endpoint_auth_signing_alg</c> excludes <c>none</c> and
/// <c>backchannel_authentication_request_signing_alg</c> excludes both <c>none</c> and the symmetric
/// HS* algorithms. The same provider feeds the discovery document, so DCR accepts exactly what the
/// server advertises.
/// </summary>
/// <param name="jwtAlgorithms">Source of the per-parameter supported signing algorithm sets.</param>
public class SigningAlgorithmsValidator(IJwtAlgorithmsProvider jwtAlgorithms) : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates the signing algorithms specified in the client registration request against the
    /// per-parameter supported sets. Each set is read only when its parameter is present, so a
    /// parameter left unset never touches the corresponding provider property.
    /// </summary>
    /// <param name="context">The validation context containing the client registration data.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if any signing algorithm is not supported;
    /// otherwise, null if all validations are successful.
    /// </returns>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        // request_object_signing_alg may legitimately be "none" (OIDC Core §6.1 — an unsigned request
        // object delivered over TLS), so it is validated against the full supported set.
        if (request.RequestObjectSigningAlg is { } requestObjectAlg &&
            !jwtAlgorithms.SigningAlgorithmsSupported.Contains(requestObjectAlg, StringComparer.Ordinal))
            return NotSupported(Parameters.RequestObjectSigningAlg);

        if (request.BackChannelAuthenticationRequestSigningAlg is { } backChannelAlg &&
            !jwtAlgorithms.BackChannelAuthenticationRequestSigningAlgValuesSupported.Contains(
                backChannelAlg, StringComparer.Ordinal))
            return NotSupported(Parameters.BackChannelAuthenticationRequestSigningAlg);

        if (request.TokenEndpointAuthSigningAlg is { } tokenEndpointAlg &&
            !jwtAlgorithms.TokenEndpointAuthSigningAlgValuesSupported.Contains(
                tokenEndpointAlg, StringComparer.Ordinal))
            return NotSupported(Parameters.TokenEndpointAuthSigningAlg);

        return null;
    }

    private static OidcError NotSupported(string description)
        => new(ErrorCodes.InvalidRequest, $"The signing algorithm for {description} is not supported");
}
