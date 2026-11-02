import os
import unittest

if os.name == 'posix':
    from cold_start import parse_event, program, timeline


@unittest.skipUnless(os.name == 'posix', 'Native trace imports Linux host APIs')
class ColdStartTests(unittest.TestCase):
    def test_timeline_excludes_version_checks_and_requires_actual_workload_exec(self):
        events = [parse_event(line) for line in [
            '110\tgroup\t23\t2\n',
            '111\tgroup\t24\t23\n',
            '122\texec\t4\t11\t/fixture/sandcrab\n',
            '123\tattach\t4\t24\n',
            '125\texec\t3\t24\t/tools/bwrap\n',
            '135\texec\t4\t24\t/tools/bwrap\n',
            '145\texec\t5\t24\t/bin/bash\n',
        ]]
        observed = timeline(list(reversed(events)), 100, 150, 23, '/fixture/sandcrab')
        self.assertEqual(observed['status'], 'COMPLETE')
        self.assertEqual(observed['nanosecondsFromSubmit']['bwrapSandboxExec'], 35)
        self.assertEqual(observed['nanosecondsFromSubmit']['launcherPlaced'], 23)
        self.assertEqual(observed['placementObservation'], 'cgroup-attach-task')
        incomplete = timeline(events[:-1], 100, 150, 23, '/fixture/sandcrab')
        self.assertEqual(incomplete['status'], 'INCOMPLETE')
        self.assertEqual(incomplete['missing'], ['bashExec'])
        missing_launcher = [event for event in events if event.get('filename') != '/fixture/sandcrab']
        self.assertIn('bwrapSandboxExec', timeline(missing_launcher, 100, 150, 23, '/fixture/sandcrab')['missing'])
        recycled_pid = [*events, parse_event('130\texit\t4\t24\n')]
        self.assertIn('bwrapSandboxExec', timeline(recycled_pid, 100, 150, 23, '/fixture/sandcrab')['missing'])
        unrelated_group = [{**event, 'cgroupId': 99} if event['event'] == 'cgroup-placement' else event
                           for event in events]
        self.assertIn('bwrapSandboxExec', timeline(unrelated_group, 100, 150, 23, '/fixture/sandcrab')['missing'])
        no_placement = [event for event in events if event['event'] != 'cgroup-placement']
        self.assertIn('launcherPlaced', timeline(no_placement, 100, 150, 23, '/fixture/sandcrab')['missing'])

    def test_clone_placement_requires_birth_and_exec_in_the_session_tree(self):
        events = [parse_event(line) for line in [
            '101\tgroup\t99\t2\n',
            '102\tbirth\t9\t99\n',
            '103\texec\t9\t99\t/fixture/sandcrab\n',
            '104\texec\t9\t99\t/tools/bwrap\n',
            '105\texec\t10\t99\t/bin/bash\n',
            '110\tgroup\t23\t2\n',
            '111\tgroup\t24\t23\n',
            '120\tbirth\t4\t24\n',
            '122\texec\t4\t24\t/fixture/sandcrab\n',
            '125\texec\t3\t24\t/tools/bwrap\n',
            '135\texec\t4\t24\t/tools/bwrap\n',
            '145\texec\t5\t24\t/bin/bash\n',
        ]]
        observed = timeline(events, 100, 150, 23, '/fixture/sandcrab')
        self.assertEqual(observed['status'], 'COMPLETE')
        self.assertEqual(observed['placementObservation'], 'sched-process-fork-child-cgroup')
        self.assertEqual(observed['nanosecondsFromSubmit']['launcherPlaced'], 20)
        self.assertEqual(observed['nanosecondsFromSubmit']['trustedLauncherExec'], 22)
        self.assertEqual(observed['nanosecondsFromSubmit']['bwrapSandboxExec'], 35)
        self.assertEqual(observed['nanosecondsFromSubmit']['bashExec'], 45)
        for invalid in [
            [event for event in events if event['event'] != 'process-birth'],
            [{**event, 'cgroupId': 99} if event['event'] == 'process-birth' else event for event in events],
            [*events, parse_event('121\texit\t4\t24\n')],
        ]:
            self.assertIn('launcherPlaced', timeline(invalid, 100, 150, 23, '/fixture/sandcrab')['missing'])

    def test_unowned_namespace_and_ambiguous_event_are_rejected(self):
        with self.assertRaises(ValueError):
            program('arbitrary; source', 1, 2)
        with self.assertRaises(ValueError):
            parse_event('100\texec\t1\n')


if __name__ == '__main__':
    unittest.main()
