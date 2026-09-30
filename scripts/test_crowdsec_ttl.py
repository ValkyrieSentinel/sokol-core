"""Regression for the observed 298-second smoke failure and wrong TTL controls."""
import unittest
from check_crowdsec_ttl import seconds, verify

IP = '10.231.0.6'
# Actual failed x86_64 CI run 36703442463: ceil(4m57.828609206s) is 298, not 299/300.
DURATION = '4m57.828609206s'
ADAPTER = ('SIGNAL#15001;ttl=298:crowdsec|10.231.0.6|-|sokol smoke ban '
           '(origin cscli, crowdsec duration 4m57.828609206s) (Applied)')
NODE = ('Dynamic block enforced in XDP: 10.231.0.6 for 298s | Reason: '
        'crowdsec: sokol smoke ban (origin cscli, crowdsec duration 4m57.828609206s)')


class CrowdSecTTL(unittest.TestCase):
    def test_actual_delayed_decision_is_correct(self):
        self.assertEqual(verify(ADAPTER, NODE, IP), 298)
        # Delivery may be acknowledged as a duplicate after an earlier ACK was lost.
        self.assertEqual(verify(ADAPTER.replace('(Applied)', '(Duplicate)'), NODE, IP), 298)

    def test_rounding_and_units(self):
        for raw, expected in [('5m', 300), ('4m58.398547965s', 299),
                              ('1m0.000000001s', 61), ('500ms', 1), ('1us', 1)]:
            with self.subTest(raw=raw):
                self.assertEqual(seconds(raw), expected)
        for raw in ['0s', '-1s', '301s', '5m1s', 'NaNs', '', '4m trailing', '1.2.3s']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                seconds(raw)

    def test_wrong_rounding_node_escalation_and_inconsistent_reason_fail(self):
        bad = [
            (ADAPTER.replace('ttl=298', 'ttl=297'), NODE),
            (ADAPTER, NODE.replace('for 298s', 'for 900s')),
            (ADAPTER.replace('ttl=298', 'ttl=299'), NODE.replace('for 298s', 'for 299s')),
            (ADAPTER, NODE.replace(DURATION, '4m58s')),
            (ADAPTER.replace(IP, '10.231.0.7'), NODE),
            (ADAPTER, ''),
            (ADAPTER + '\n' + ADAPTER, NODE),
        ]
        for sent, enforced in bad:
            with self.subTest(sent=sent, enforced=enforced), self.assertRaises(ValueError):
                verify(sent, enforced, IP)


if __name__ == '__main__':
    unittest.main()
