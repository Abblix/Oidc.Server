// Abblix OIDC Server Library
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
