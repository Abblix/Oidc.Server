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
