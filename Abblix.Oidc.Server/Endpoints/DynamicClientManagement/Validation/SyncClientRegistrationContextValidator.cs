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

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// This abstract class provides a base for synchronous client registration context validators.
/// It implements the ValidateAsync method from the IClientRegistrationContextValidator interface
/// by calling the abstract Validate method and wrapping the result in a Task.
/// </summary>
public abstract class SyncClientRegistrationContextValidator : IClientRegistrationContextValidator
{
    public Task<ClientRegistrationValidationError?> ValidateAsync(ClientRegistrationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Validates the client registration context synchronously and returns a ClientRegistrationValidationError if validation fails,
    /// or null if the context is valid. Derived classes must implement this method.
    /// </summary>
    /// <param name="context">The validation context containing client registration information.</param>
    /// <returns>A ClientRegistrationValidationError if validation fails, or null if the context is valid.</returns>
    protected abstract ClientRegistrationValidationError? Validate(ClientRegistrationValidationContext context);
}
