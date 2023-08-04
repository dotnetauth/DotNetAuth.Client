using DotNetAuth.Client;

namespace DotNetAuth.ClientTests.Mocks
{
    class StateStoreMock : IStateStore
    {
        private readonly Func<string> getStateFun;
        private readonly Func<string?, bool> checkStateFun;

        public StateStoreMock(Func<string>? getStateFun = null, Func<string?, bool>? checkStateFun = null)
        {
            this.getStateFun = getStateFun ?? (() => "mock_state");
            this.checkStateFun = checkStateFun ?? ((_) => true);
        }

        public bool CheckState(string? state) => checkStateFun(state);

        public string GetState() => getStateFun();
    }
}