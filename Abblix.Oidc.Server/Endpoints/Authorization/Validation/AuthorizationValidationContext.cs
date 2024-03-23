// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
