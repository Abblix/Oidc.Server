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


namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// Thrown when a request is not one this client will attach a token to.
/// </summary>
/// <remarks>
/// A configuration failure rather than a protocol one, and the request never leaves. Refusing is the point:
/// the alternatives are sending a bearer credential over plain HTTP, or to a host it was not issued for,
/// both of which succeed quietly and are discovered by someone else.
/// </remarks>
public sealed class AccessTokenPresentationException(string message) : Exception(message);
