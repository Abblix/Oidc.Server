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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

public class CompositeRequestFetcher : IAuthorizationRequestFetcher
{
    public CompositeRequestFetcher(IAuthorizationRequestFetcher[] fetchers)
    {
        _fetchers = fetchers;
    }

    private readonly IAuthorizationRequestFetcher[] _fetchers;

    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        foreach (var fetcher in _fetchers)
        {
            var result = await fetcher.FetchAsync(request);
            switch (result)
            {
                case FetchResult.Success success:
                    request = success.Request;
                    continue;

                case FetchResult.Fault fault:
                    return fault;

                default:
                    throw new UnexpectedTypeException(nameof(result), result.GetType());
            }
        }

        return request;
    }
}
