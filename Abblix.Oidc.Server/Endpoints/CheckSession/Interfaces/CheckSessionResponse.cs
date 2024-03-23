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

namespace Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;

/// <summary>
/// Represents the response to a check session request in OpenID Connect Session Management.
/// This record contains the necessary information to ascertain the current state of a user session.
/// </summary>
/// <param name="HtmlContent">The HTML content to be rendered, typically used in an iframe for session checking.</param>
/// <param name="CacheKey">An object that represents a cache key, used for optimizing session state checks.
/// It serves as a key for caching the response to reduce frequent reevaluation when the session state is expected
/// to remain unchanged for an extended period, enhancing performance.</param>
public record CheckSessionResponse(string HtmlContent, object CacheKey);
