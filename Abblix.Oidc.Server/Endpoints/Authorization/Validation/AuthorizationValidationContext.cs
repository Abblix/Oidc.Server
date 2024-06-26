﻿// Abblix OIDC Server Library
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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Represents a validation context containing information about the client, response mode, and flow type
/// that is used during the authorization request validation process.
/// </summary>
public record AuthorizationValidationContext(AuthorizationRequest Request)
{
	/// <summary>
	/// The request object to validate.
	/// </summary>
	public AuthorizationRequest Request { get; set; } = Request;

	private ClientInfo? _clientInfo;

	/// <summary>
	/// The ClientInfo object containing information about the client. It is a result of identifying the client
	/// making the authorization request.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when attempting to get a null value.</exception>
	public ClientInfo ClientInfo { get => _clientInfo.NotNull(nameof(ClientInfo)); set => _clientInfo = value; }

	/// <summary>
	/// The response mode associated with the authorization request, determining how the authorization response
	/// should be delivered to the client.
	/// </summary>
	public string ResponseMode = ResponseModes.Query;

	private FlowTypes? _flowType;

	/// <summary>
	/// The flow type associated with the authorization request, indicating the OAuth 2.0 flow being utilized
	/// (e.g., Authorization Code, Implicit).
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when attempting to get a null value.</exception>
	public FlowTypes FlowType { get => _flowType.NotNull(nameof(FlowType)); set => _flowType = value; }

	/// <summary>
	/// The validated and approved redirect URI for the authorization response.
	/// This URI must match one of the URIs registered by the client.
	/// </summary>
	public Uri? ValidRedirectUri { get; set; }
}
