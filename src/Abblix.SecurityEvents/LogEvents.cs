// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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

    /// <summary>
    /// Back-channel logout intake: range 1100-1199.
    /// </summary>
    public static class BackChannelLogout
    {
        private const int Base = 1100;

        /// <summary>
        /// A logout request was refused; the message carries the error code and the description
        /// that travelled back to the provider.
        /// </summary>
        public const int RequestRefused = Base + 1;
    }
}
