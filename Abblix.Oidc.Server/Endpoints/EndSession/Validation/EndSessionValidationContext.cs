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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Represents the context for validating an end-session request.
/// </summary>
public record EndSessionValidationContext(EndSessionRequest Request)
{
	/// <summary>
	/// The request object to validate.
	/// </summary>
	public EndSessionRequest Request { get; set; } = Request;

	/// <summary>
	/// The ClientId associated with the request.
	/// </summary>
	public string? ClientId { get; set; } = Request.ClientId;

	/// <summary>
	/// The ClientInfo object containing information about the client.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when attempting to get a null value.</exception>
	public ClientInfo? ClientInfo { get; set; }

	/// <summary>
	/// The ID token associated with the end-session request.
	/// This token is typically used to validate the identity of the user who initiated the end-session process.
	/// </summary>
	public JsonWebToken? IdToken { get; set; }
}
