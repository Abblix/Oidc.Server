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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.EndSession;

public class EndSessionHandler : IEndSessionHandler
{
    public EndSessionHandler(
        IEndSessionRequestValidator validator,
        IEndSessionRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IEndSessionRequestValidator _validator;
    private readonly IEndSessionRequestProcessor _processor;

    public async Task<EndSessionResponse> HandleAsync(Model.EndSessionRequest endSessionRequest)
    {
        var validationResult = await _validator.ValidateAsync(endSessionRequest);

        var response = validationResult switch
        {
            ValidEndSessionRequest validRequest => await _processor.ProcessAsync(validRequest),

            EndSessionRequestValidationError { Error: var error, ErrorDescription: var description }
                => new EndSessionErrorResponse(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType())
        };
        return response;
    }
}
