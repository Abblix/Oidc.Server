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

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Represents the licensing constraints applied to the application, including limits on the number of clients and issuers,
/// as well as the validity period of the license.
/// </summary>
/// <remarks>
/// This record is central to defining and enforcing operational limits and licensing terms within the application. It
/// supports not only quantitative restrictions, such as the number of clients and issuers, but also temporal constraints,
/// specifying when the license is valid and providing a grace period beyond the expiration date.
///
/// Properties:
/// - <see cref="ClientLimit"/> and <see cref="IssuerLimit"/> impose limits on the number of clients and issuers
///   that can interact with the application, ensuring compliance with the licensing agreement.
/// - <see cref="ValidIssuers"/> specifies which issuers are recognized as valid sources of tokens or claims, adding
///   an additional layer of security and compliance.
/// - <see cref="NotBefore"/> and <see cref="ExpiresAt"/> define the time frame during which the license is considered
///   valid, allowing for precise control over the license's lifecycle.
/// - <see cref="GracePeriod"/> offers flexibility by defining a period after <see cref="ExpiresAt"/> during which the
///   license constraints are still enforced, but the application may remain operational to account for renewal
///   processes.
///
/// Together, these properties enable a robust and flexible approach to licensing, facilitating compliance, security,
/// and operational continuity.
/// </remarks>
public record License
{
    /// <summary>
    /// The maximum number of clients that are allowed to interact with the application under the current license.
    /// </summary>
    /// <remarks>
    /// This property specifies a limit on the number of unique client applications that can be registered or authenticated
    /// by the application. It's a crucial aspect of licensing enforcement, ensuring that the application usage does not
    /// exceed the terms agreed upon in the licensing contract. A value of <c>null</c> indicates that there is no limit on
    /// the number of clients.
    ///
    /// When the number of unique clients exceeds this limit, the application should enforce the licensing terms by
    /// restricting further client registrations or authentications, aligning with the compliance requirements.
    /// </remarks>
    public int? ClientLimit { get; init; }

    /// <summary>
    /// The maximum number of issuers that are recognized as valid by the application under the current license.
    /// </summary>
    /// <remarks>
    /// This property defines a cap on the number of distinct issuers from which the application will accept tokens or
    /// claims. It plays a vital role in controlling access and ensuring that the application's interactions are within
    /// the bounds set by its licensing terms. A <c>null</c> value for this property implies that there's no restriction
    /// on the number of issuers.
    ///
    /// Exceeding this limit may require the application to implement measures that block tokens or claims issued by
    /// additional issuers, thereby maintaining adherence to the licensing agreement.
    /// </remarks>
    public int? IssuerLimit { get; init; }

    /// <summary>
    /// An array of strings representing the issuers that are considered valid for this license.
    /// </summary>
    public HashSet<string>? ValidIssuers { get; init; }

    /// <summary>
    /// The date and time before which the license is not valid.
    /// </summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>
    /// The expiration date and time of the license.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// An optional grace period after the expiration date during which the license conditions are still considered valid.
    /// </summary>
    public DateTimeOffset? GracePeriod { get; init; }
}
