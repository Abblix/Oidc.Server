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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Defines a contract for processing requests to remove or deregister clients from an OAuth 2.0 or OpenID Connect
/// compliant system.
/// </summary>
/// <remarks>
/// Implementations of this interface are responsible for the validation and execution of client removal operations,
/// ensuring that requests are authorized and that the removal aligns with security and protocol standards.
/// </remarks>
public interface IRemoveClientRequestProcessor
{
    /// <summary>
    /// Asynchronously processes a request to remove a client, ensuring the request is authorized and valid before
    /// proceeding with the unregistration.
    /// </summary>
    /// <param name="request">A <see cref="ValidClientRequest"/> that has been validated and contains the necessary
    /// information to identify and remove the specified client.</param>
    /// <returns>A <see cref="Task"/> that upon completion yields a <see cref="RemoveClientResponse"/>,
    /// indicating the outcome of the removal operation.</returns>
    /// <remarks>
    /// This method is central to maintaining the integrity of the client registry by allowing for the removal
    /// of clients that are no longer active or authorized. Implementations should ensure that the removal process
    /// adheres to the system's security policies and the specifications of the OAuth 2.0 and OpenID Connect protocols.
    /// </remarks>
    Task<RemoveClientResponse> ProcessAsync(ValidClientRequest request);
}
