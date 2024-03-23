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

using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Dynamically determines the issuer identifier based on the incoming HTTP request.
/// This approach allows the issuer identifier to reflect the actual request's context,
/// accommodating scenarios like varying host names or different environments.
/// </summary>
internal class RequestBasedIssuerProvider : IIssuerProvider
{
	/// <summary>
	/// Initializes a new instance of the <see cref="RequestBasedIssuerProvider"/> class.
	/// </summary>
	/// <param name="requestInfoProvider">The provider that supplies information about the current HTTP request.</param>
	public RequestBasedIssuerProvider(IRequestInfoProvider requestInfoProvider)
	{
		_requestInfoProvider = requestInfoProvider;
	}

	private readonly IRequestInfoProvider _requestInfoProvider;

	/// <summary>
	/// Retrieves the issuer identifier based on the current HTTP request.
	/// </summary>
	/// <returns>The issuer identifier, constructed from the request's context.</returns>
	public string GetIssuer() => _requestInfoProvider.ApplicationUri;
}
