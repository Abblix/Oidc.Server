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

using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Defines the interface for a service that converts user subject identifiers according to the client's specified
/// subject type. This conversion ensures that the subject identifier presented to the client is in the format
/// that the client expects, based on its configuration.
/// </summary>
/// <remarks>
/// The implementation of this interface should support various subject types, such as "public" or "pairwise",
/// and provide appropriate conversions based on the OpenID Connect specifications.
/// </remarks>
public interface ISubjectTypeConverter
{
    /// <summary>
    /// Lists the subject types that this converter supports. This typically includes "public" and "pairwise"
    /// among others, depending on the OpenID Connect implementation specifics.
    /// </summary>
    IEnumerable<string> SubjectTypesSupported { get; }

    /// <summary>
    /// Converts the subject identifier for an end-user based on the client's subject type.
    /// </summary>
    /// <param name="subject">The original subject identifier of the end-user.</param>
    /// <param name="clientInfo">Information about the client for which the subject identifier is being transformed.
    /// </param>
    /// <returns>The transformed subject identifier suitable for the client's subject type.</returns>
    string Convert(string subject, ClientInfo clientInfo);
}
