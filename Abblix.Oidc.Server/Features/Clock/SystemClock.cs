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

namespace Abblix.Oidc.Server.Features.Clock;

#if NET8_0_OR_GREATER

/// <summary>
/// Represents a clock providing the current time, where the time source can be configured through a <see cref="TimeProvider"/>.
/// This version is specifically for use with .NET 8.0 or greater, allowing for more flexible time source configurations.
/// </summary>
/// <param name="timeProvider">A <see cref="TimeProvider"/> instance that defines how the current time is obtained.</param>
public class SystemClock(TimeProvider timeProvider) : IClock
{
   /// <summary>
    /// Gets the current UTC time as provided by the configured <see cref="TimeProvider"/>.
    /// </summary>
    public DateTimeOffset UtcNow => timeProvider.GetUtcNow();
}

#else

/// <summary>
/// Represents a clock that provides the current UTC time based on the system clock.
/// This implementation is intended for use in versions of .NET earlier than 8.0, relying on the system's clock.
/// </summary>
public class SystemClock : IClock
{
    /// <summary>
    /// Gets the current UTC time directly from the system clock.
    /// </summary>
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

#endif
