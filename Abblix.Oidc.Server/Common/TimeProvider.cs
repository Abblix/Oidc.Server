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

#if !NET8_0_OR_GREATER

// ReSharper disable once CheckNamespace
namespace System;

/// <summary>
/// Represents a clock that provides the current UTC time based on the system clock.
/// This implementation is intended for use in environments or versions of .NET earlier than 8.0,
/// where access to a more precise or configurable time source is not required. It abstracts the
/// mechanism for obtaining time, allowing for more flexible testing or future changes to time
/// acquisition strategies without altering dependent code.
/// </summary>
public abstract class TimeProvider
{
    /// <summary>
    /// Gets the current UTC time directly from the system clock.
    /// This abstract method must be implemented by subclasses to return the current UTC time,
    /// allowing different strategies for time retrieval, such as fixed time for testing or
    /// alternate time sources.
    /// </summary>
    /// <returns>The current UTC time as a <see cref="DateTimeOffset"/>.</returns>
    public abstract DateTimeOffset GetUtcNow();

    /// <summary>
    /// Provides a singleton instance of the <see cref="TimeProvider"/> that retrieves the current time
    /// using the system's default clock, specifically <see cref="DateTimeOffset.UtcNow"/>.
    /// This standard implementation is thread-safe and efficient, suitable for general use across various
    /// application components.
    /// </summary>
    public static readonly TimeProvider System = new SystemTimeProvider();

    /// <summary>
    /// A private nested class that provides the system time. This class implements the
    /// <see cref="TimeProvider.GetUtcNow"/> method using the system's clock.
    /// </summary>
    private class SystemTimeProvider : TimeProvider
    {
        /// <summary>
        /// Returns the current UTC time from the system's clock.
        /// This method directly accesses <see cref="DateTimeOffset.UtcNow"/> to provide the current time,
        /// ensuring that time retrievals are fast and reflect the actual system time with no adjustments or modifications.
        /// </summary>
        /// <returns>The current UTC time as a <see cref="DateTimeOffset"/>.</returns>
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow;
    }
}

#endif
