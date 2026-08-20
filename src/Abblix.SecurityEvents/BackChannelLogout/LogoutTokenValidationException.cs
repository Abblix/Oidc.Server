// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// Thrown when a Logout Token failed one of the validation steps of section 2.6.
/// </summary>
/// <remarks>
/// Section 2.6 names the answer that goes with it: "If any of the validation steps fails, reject the Logout
/// Token and return an HTTP 400 Bad Request error."
/// </remarks>
public sealed class LogoutTokenValidationException(string message) : Exception(message);
