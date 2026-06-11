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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the algorithms a client requests for tokens this server signs:
/// <c>id_token_signed_response_alg</c> and <c>userinfo_signed_response_alg</c> (OIDC DCR 1.0 §2), and
/// <c>authorization_signed_response_alg</c> (JARM §3). Each must appear in the server's set of supported
/// signing algorithms; in addition, JARM §3 forbids <c>none</c> for the authorization response.
/// </summary>
/// <param name="jwtAlgorithms">Source of supported signing algorithms for outbound tokens. The same
/// provider feeds the discovery document, so DCR accepts exactly what the server advertises —
/// in particular HS* stays rejected here for the same key-availability reason it is not
/// advertised (client secrets are stored hashed and cannot serve as HMAC keys).</param>
public class SignedResponseAlgorithmsValidator(IJwtAlgorithmsProvider jwtAlgorithms) : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates the signing algorithms specified for ID tokens, user info and JARM authorization responses.
    /// This method ensures that the JWT creator supports the requested algorithms.
    /// </summary>
    /// <param name="context">The validation context containing the client registration data.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if any signing algorithm is not supported;
    /// otherwise, null if all validations are successful.
    /// </returns>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        return ValidateIdTokenSignedResponseAlg(request) ??
               Validate(request.UserInfoSignedResponseAlg, Parameters.UserInfoSignedResponseAlg) ??
               Validate(request.IntrospectionSignedResponseAlg, Parameters.IntrospectionSignedResponseAlg) ??
               ValidateAuthorizationSignedResponseAlg(request.AuthorizationSignedResponseAlg);
    }

    /// <summary>
    /// Validates <c>id_token_signed_response_alg</c>. OIDC Registration 1.0 §2: the value none MUST
    /// NOT be used unless the client uses only response types that return no ID Token from the
    /// authorization endpoint — an unsigned ID Token delivered through the browser would be
    /// modifiable in transit.
    /// </summary>
    private OidcError? ValidateIdTokenSignedResponseAlg(Model.ClientRegistrationRequest request)
    {
        if (string.Equals(request.IdTokenSignedResponseAlg, SigningAlgorithms.None, StringComparison.Ordinal) &&
            Array.Exists(request.ResponseTypes, responseType => responseType.Contains(ResponseTypes.IdToken)))
        {
            return new OidcError(
                ErrorCodes.InvalidClientMetadata,
                $"The algorithm '{SigningAlgorithms.None}' is not allowed for {Parameters.IdTokenSignedResponseAlg} " +
                $"when the registered response types return an ID Token from the authorization endpoint");
        }

        return Validate(request.IdTokenSignedResponseAlg, Parameters.IdTokenSignedResponseAlg);
    }

    /// <summary>
    /// Validates <c>authorization_signed_response_alg</c> for JARM. In addition to the supported-algorithm
    /// check, JARM §3 explicitly forbids the <c>none</c> algorithm for the authorization response.
    /// </summary>
    private OidcError? ValidateAuthorizationSignedResponseAlg(string? alg)
    {
        if (string.Equals(alg, SigningAlgorithms.None, StringComparison.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The algorithm '{SigningAlgorithms.None}' is not allowed for {Parameters.AuthorizationSignedResponseAlg}");
        }

        return Validate(alg, Parameters.AuthorizationSignedResponseAlg);
    }

    /// <summary>
    /// Validates that the JWT creator supports the specified signing algorithm.
    /// If the algorithm is not supported, it returns a validation error.
    /// </summary>
    /// <param name="alg">The signing algorithm to validate.</param>
    /// <param name="description">
    /// A description used in the error message to identify which signing algorithm is invalid.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the algorithm is not supported; otherwise, null.
    /// </returns>
    private OidcError? Validate(string? alg, string description)
    {
        if (alg is not null && !jwtAlgorithms.SignedResponseAlgorithmsSupported.Contains(alg, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The signing algorithm for {description} is not supported");
        }

        return null;
    }
}
