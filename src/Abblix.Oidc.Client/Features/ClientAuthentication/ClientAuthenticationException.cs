// Abblix OIDC Client Library
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


namespace Abblix.Oidc.Client.Features.ClientAuthentication;

/// <summary>
/// Thrown when this client cannot present the credentials it was configured to present.
/// </summary>
/// <remarks>
/// A configuration failure, not a protocol one: the request never leaves. It is deliberately loud rather
/// than a silent fall back to an unauthenticated request, which would turn a confidential client into a
/// public one at the moment its secret went missing.
/// </remarks>
public sealed class ClientAuthenticationException(string message) : Exception(message);
