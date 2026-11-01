import os
import unittest

if os.name == 'posix':
    from cold_start import parse_event, program, timeline


@unittest.skipUnless(os.name == 'posix', 'Native trace imports Linux host APIs')
class ColdStartTests(unittest.TestCase):
    def test_timeline_excludes_version_checks_and_requires_actual_workload_exec(self):
        events = [parse_event(line) for line in [
            '105\texec\t1\t11\t/usr/bin/busctl\n',
            '110\tgroup\t23\n',
            '120\texec\t2\t11\t/usr/bin/systemd-run\n',
            '122\texec\t4\t24\t/fixture/sandcrab\n',
            '125\texec\t3\t24\t/tools/bwrap\n',
            '135\texec\t4\t24\t/tools/bwrap\n',
            '145\texec\t5\t24\t/bin/bash\n',
        ]]
        observed = timeline(list(reversed(events)), 100, 150, 23, '/fixture/sandcrab')
        self.assertEqual(observed['status'], 'COMPLETE')
        self.assertEqual(observed['nanosecondsFromSubmit']['bwrapSandboxExec'], 35)
        incomplete = timeline(events[:-1], 100, 150, 23, '/fixture/sandcrab')
        self.assertEqual(incomplete['status'], 'INCOMPLETE')
        self.assertEqual(incomplete['missing'], ['bashExec'])
        missing_launcher = [event for event in events if event.get('filename') != '/fixture/sandcrab']
        self.assertIn('bwrapSandboxExec', timeline(missing_launcher, 100, 150, 23, '/fixture/sandcrab')['missing'])
        recycled_pid = [*events, parse_event('130\texit\t4\t24\n')]
        self.assertIn('bwrapSandboxExec', timeline(recycled_pid, 100, 150, 23, '/fixture/sandcrab')['missing'])
        unrelated_group = [{**event, 'cgroupId': 99} if event.get('filename') == '/fixture/sandcrab' else event
                           for event in events]
        self.assertIn('bwrapSandboxExec', timeline(unrelated_group, 100, 150, 23, '/fixture/sandcrab')['missing'])

    def test_unowned_namespace_and_ambiguous_event_are_rejected(self):
        with self.assertRaises(ValueError):
            program('arbitrary; source', 1, 2)
        with self.assertRaises(ValueError):
            parse_event('100\texec\t1\n')


if __name__ == '__main__':
    unittest.main()
