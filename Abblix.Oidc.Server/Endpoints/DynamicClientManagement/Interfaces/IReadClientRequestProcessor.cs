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
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Builds the RFC 7592 §2.1 read-client response from a request that has already been validated.
/// Reads stored metadata, formats it for the wire, and issues a fresh
/// <c>registration_access_token</c> as recommended by RFC 7592 §3.
/// </summary>
public interface IReadClientRequestProcessor
{
    /// <summary>
    /// Produces the response payload for the addressed client, including its current metadata
    /// and a refreshed registration access token.
    /// </summary>
    /// <param name="request">A request whose authentication and target client have been validated.</param>
    Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request);
}
