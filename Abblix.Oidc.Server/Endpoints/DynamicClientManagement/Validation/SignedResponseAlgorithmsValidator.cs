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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the signing algorithms specified for ID tokens and user info responses in a client registration request.
/// This class checks if the requested signing algorithms are supported by the JWT creator, ensuring compliance
/// with security standards.
/// </summary>
public class SignedResponseAlgorithmsValidator: SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SignedResponseAlgorithmsValidator"/> class.
    /// The constructor takes a JWT creator to access the supported signing algorithms for validation.
    /// </summary>
    /// <param name="jwtCreator">The service responsible for creating signed JWTs.</param>
    public SignedResponseAlgorithmsValidator(IJsonWebTokenCreator jwtCreator)
    {
        _jwtCreator = jwtCreator;
    }

    private readonly IJsonWebTokenCreator _jwtCreator;

    /// <summary>
    /// Validates the signing algorithms specified for ID tokens and user info responses.
    /// This method ensures that the JWT creator supports the requested algorithms.
    /// </summary>
    /// <param name="context">The validation context containing the client registration data.</param>
    /// <returns>
    /// A <see cref="ClientRegistrationValidationError"/> if any signing algorithm is not supported;
    /// otherwise, null if all validations are successful.
    /// </returns>
    protected override ClientRegistrationValidationError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        return Validate( request.IdTokenSignedResponseAlg, Parameters.IdTokenSignedResponseAlg) ??
               Validate(request.UserInfoSignedResponseAlg, Parameters.UserInfoSignedResponseAlg);
    }

    /// <summary>
    /// Validates that the JWT creator supports the specified signing algorithm.
    /// If the algorithm is not supported, it returns a validation error.
    /// </summary>
    /// <param name="alg">The signing algorithm to validate.</param>
    /// <param name="description">
    /// A description used in the error message to identify which signing algorithm is invalid.</param>
    /// <returns>
    /// A <see cref="ClientRegistrationValidationError"/> if the algorithm is not supported; otherwise, null.
    /// </returns>
    private ClientRegistrationValidationError? Validate(string? alg, string description)
    {
        if (alg is not null && !_jwtCreator.SignedResponseAlgorithmsSupported.Contains(alg, StringComparer.Ordinal))
        {
            return new ClientRegistrationValidationError(
                ErrorCodes.InvalidRequest,
                $"The signing algorithm for {description} is not supported");
        }

        return null;
    }
}
