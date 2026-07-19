using System.Threading;

namespace Abblix.DependencyInjection.UnitTests.Model;

public class ServiceA : IPrimaryService, IAliasService
{
    private static int _instanceCounter;
    private readonly int _instanceId;

    public ServiceA()
    {
        _instanceId = Interlocked.Increment(ref _instanceCounter);
    }

    public string GetValue() => $"ServiceA-{_instanceId}";
}
