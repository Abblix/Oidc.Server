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
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using IntrospectionRequest = Abblix.Oidc.Server.Model.IntrospectionRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the result of a token introspection request into an <see cref="IResult"/>.</summary>
public interface IIntrospectionResponseFormatter
{
    /// <summary>Formats the introspection result (RFC 7662 JSON or RFC 9701 JWT on success, OAuth error otherwise).</summary>
    Task<IResult> FormatResponseAsync(IntrospectionRequest request, Result<IntrospectionSuccess, OidcError> response);
}
