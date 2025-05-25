using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.Extensions.Configuration;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

public class ConfigurableRouteConventionTests
{
    public ConfigurableRouteConventionTests()
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .Build();

        var routesSection = configuration.GetSection("Routes");
        _convention = new ConfigurableRouteConvention(Path.RoutePrefix, routesSection);
    }

    private readonly ConfigurableRouteConvention _convention;

    [Theory]
    [InlineData(Path.Authorize,                  "~/connect/authorize")]
    [InlineData(Path.PushAuthorizationRequest,   "~/connect/par")]
    [InlineData(Path.UserInfo,                   "~/connect/userinfo")]
    [InlineData(Path.EndSession,                 "~/connect/endsession")]
    [InlineData(Path.CheckSession,               "~/connect/checksession")]
    [InlineData(Path.Token,                      "~/connect/token")]
    [InlineData(Path.Revocation,                 "~/connect/revoke")]
    [InlineData(Path.Introspection,              "~/connect/introspect")]
    [InlineData(Path.BackChannelAuthentication,  "~/connect/bc-authorize")]
    [InlineData(Path.DeviceAuthorization,        "~/connect/deviceauthorization")]
    [InlineData(Path.Register,                   "~/connect/register")]
    [InlineData(Path.Configuration,              "~/.well-known/openid-configuration")]
    [InlineData(Path.Keys,                       "~/.well-known/jwks")]
    public void Resolve_AllPathConstants_ReturnExpected(string template, string expected)
        => Assert.Equal(expected, _convention.Resolve(template));
}
