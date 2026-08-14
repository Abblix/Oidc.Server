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


namespace Abblix.SharedSignals.Receiver.BackChannelLogout;

/// <summary>
/// Thrown when a Logout Token failed one of the validation steps of section 2.6.
/// </summary>
/// <remarks>
/// Section 2.6 names the answer that goes with it: "If any of the validation steps fails, reject the Logout
/// Token and return an HTTP 400 Bad Request error."
/// </remarks>
public sealed class LogoutTokenValidationException(string message) : Exception(message);
