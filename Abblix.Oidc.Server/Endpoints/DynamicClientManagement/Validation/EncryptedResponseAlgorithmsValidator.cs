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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the JWE algorithms a client requests for the JWTs this server encrypts or decrypts:
/// <c>id_token_encrypted_response_alg</c>/<c>enc</c> and <c>userinfo_encrypted_response_alg</c>/<c>enc</c>
/// (OIDC Core), <c>request_object_encryption_alg</c>/<c>enc</c> (RFC 9101) and
/// <c>authorization_encrypted_response_alg</c>/<c>enc</c> (JARM §3). Each key-management (<c>alg</c>) value
/// must appear in the server's supported key-management algorithms and each content-encryption (<c>enc</c>)
/// value in its supported content-encryption algorithms.
/// </summary>
/// <param name="jwtValidator">Source of the JWE algorithms the server supports (the registered encryptors).</param>
public class EncryptedResponseAlgorithmsValidator(IJsonWebTokenValidator jwtValidator)
    : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        return ValidateAlg(request.IdTokenEncryptedResponseAlg, Parameters.IdTokenEncryptedResponseAlg)
            ?? ValidateEnc(request.IdTokenEncryptedResponseEnc, Parameters.IdTokenEncryptedResponseEnc)
            ?? ValidateAlg(request.UserInfoEncryptedResponseAlg, Parameters.UserInfoEncryptedResponseAlg)
            ?? ValidateEnc(request.UserInfoEncryptedResponseEnc, Parameters.UserInfoEncryptedResponseEnc)
            ?? ValidateAlg(request.RequestObjectEncryptionAlg, Parameters.RequestObjectEncryptionAlg)
            ?? ValidateEnc(request.RequestObjectEncryptionEnc, Parameters.RequestObjectEncryptionEnc)
            ?? ValidateAlg(request.AuthorizationEncryptedResponseAlg, Parameters.AuthorizationEncryptedResponseAlg)
            ?? ValidateEnc(request.AuthorizationEncryptedResponseEnc, Parameters.AuthorizationEncryptedResponseEnc);
    }

    /// <summary>
    /// Validates a JWE key-management (<c>alg</c>) value against the server's supported key-management algorithms.
    /// </summary>
    private OidcError? ValidateAlg(string? alg, string description)
    {
        if (alg is not null && !jwtValidator.EncryptionAlgorithmsSupported.Contains(alg, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The encryption key-management algorithm for {description} is not supported");
        }

        return null;
    }

    /// <summary>
    /// Validates a JWE content-encryption (<c>enc</c>) value against the server's supported content-encryption
    /// algorithms.
    /// </summary>
    private OidcError? ValidateEnc(string? enc, string description)
    {
        if (enc is not null && !jwtValidator.EncryptionMethodsSupported.Contains(enc, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The encryption method for {description} is not supported");
        }

        return null;
    }
}
