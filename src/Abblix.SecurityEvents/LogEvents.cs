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

namespace Abblix.SecurityEvents;

/// <summary>
/// The event identifiers of this assembly's structured log messages. Runbooks key off the
/// numbers, so an identifier stays stable across message-text edits; the XML docs here are the
/// canonical allocation record.
/// </summary>
public static class LogEvents
{
    /// <summary>
    /// Composition and dependency-injection wiring: range 1000-1099.
    /// </summary>
    public static class Composition
    {
        private const int Base = 1000;

        /// <summary>
        /// The composed validation profile lacks a security-critical default step under an
        /// explicit allowance; the message carries the missing steps and the reason given.
        /// </summary>
        public const int InsecureProfileAllowance = Base + 1;
    }
}
