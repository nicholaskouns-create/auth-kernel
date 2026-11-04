"""Optional real-NeMo integration smoke test. Requires pip install nemoguardrails.

Registers a host-authorized action with a real LLMRails object. It does not
invoke an LLM; the action wrapper is exercised independently for determinism.
"""
import asyncio
from gate import ExecutionGate, NonceStore, Refused
from trusted_host import HostSession, nemo_host_action


def main():
    from nemoguardrails import LLMRails, RailsConfig
    config = RailsConfig.from_content(
        colang_content='define user greet\n  "hi"\n\ndefine bot greet\n  "hello"\n\ndefine flow\n  user greet\n  bot greet\n',
        yaml_content='models: []\n',
    )
    rails = LLMRails(config)
    gate = ExecutionGate(b'local-test-only-key-32-bytes-xxxx', NonceStore())
    calls = []
    action = nemo_host_action(gate, 'guarded_transfer', lambda **kw: calls.append(kw) or 'ok')
    rails.register_action(action, name='guarded_transfer')
    args = {'destination': 'approved', 'amount': 10}
    host = HostSession(gate)
    host.approve('guarded_transfer', args, 'grant1')
    with host.activate():
        assert asyncio.run(action(**args)) == 'ok'
        try:
            asyncio.run(action(**args))
        except Refused:
            pass
        else:
            raise AssertionError('replay was accepted')
    assert len(calls) == 1
    print('NeMo registration + guarded action smoke test passed')

if __name__ == '__main__':
    main()
