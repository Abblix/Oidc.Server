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

using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

public class BackChannelAuthenticationStorage : IBackChannelAuthenticationStorage
{
	public BackChannelAuthenticationStorage(
		IEntityStorage storage,
		IAuthenticationRequestIdGenerator authenticationRequestIdGenerator)
	{
		_storage = storage;
		_authenticationRequestIdGenerator = authenticationRequestIdGenerator;
	}

	private readonly IEntityStorage _storage;
	private readonly IAuthenticationRequestIdGenerator _authenticationRequestIdGenerator;

	public async Task<string> StoreAsync(BackChannelAuthenticationRequest authenticationRequest, TimeSpan expiresIn)
	{
		var authenticationRequestId = _authenticationRequestIdGenerator.GenerateAuthenticationRequestId();

		await _storage.SetAsync(
			ToKeyString(authenticationRequestId),
			authenticationRequest,
			new StorageOptions { AbsoluteExpirationRelativeToNow = expiresIn });

		return authenticationRequestId;
	}

	public Task<BackChannelAuthenticationRequest?> TryGetAsync(string authenticationRequestId)
		=> _storage.GetAsync<BackChannelAuthenticationRequest>(ToKeyString(authenticationRequestId), true);

	private static string ToKeyString(string authenticationRequestId)
		=> $"{nameof(authenticationRequestId)}:{authenticationRequestId}";
}
