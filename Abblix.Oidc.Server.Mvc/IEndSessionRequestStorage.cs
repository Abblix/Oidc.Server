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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Defines an interface for storing and retrieving end session requests.
/// This interface is typically used in authentication flows to manage the lifecycle of end session requests.
/// </summary>
public interface IEndSessionRequestStorage
{
    /// <summary>
    /// Asynchronously stores an end session request and returns an identifier for the stored request.
    /// </summary>
    /// <param name="request">The end session request to store.</param>
    /// <returns>
    /// A task that represents the asynchronous operation.
    /// The task result contains the identifier for the stored request.
    /// </returns>
    Task<string> StoreAsync(EndSessionRequest request);

    /// <summary>
    /// Attempts to extract an end session request asynchronously using the provided request identifier.
    /// </summary>
    /// <param name="requestId">The identifier of the end session request to retrieve.</param>
    /// <returns>
    /// A task that represents the asynchronous operation.
    /// The task result contains the end session request if found, or null if no request matches the identifier.
    /// </returns>
    Task<EndSessionRequest?> TryExtractAsync(string requestId);
}
