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
using Abblix.Oidc.Server.Common.Validation;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Aggregates the messages held in a failed <c>[ApiController]</c> <c>ModelState</c> and maps them onto the OAuth
/// <c>invalid_request</c> error, delegating the message-to-<see cref="OidcError"/> mapping to the shared core
/// <see cref="ErrorFactory"/> so both transport adapters render a malformed request identically.
/// </summary>
internal static class ModelValidationError
{
    /// <summary>
    /// Maps a populated <paramref name="modelState"/> onto an <see cref="OidcError"/> describing the failure in OAuth
    /// terms.
    /// </summary>
    /// <param name="modelState">The model state populated by MVC when binding or validation failed.</param>
    /// <returns>An <see cref="OidcError"/> with the <c>invalid_request</c> code.</returns>
    public static OidcError InvalidRequest(ModelStateDictionary modelState) => ErrorFactory.InvalidRequest(
        from entry in modelState
        from error in entry.Value.Errors
        select error.ErrorMessage);
}
