import contextlib
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs
import xml.etree.ElementTree as ET

import new_pa_cleanup as cleanup


FIXTURE = Path(__file__).parent / 'fixtures' / 'lab.xml'
Key = cleanup.ObjectKey


def config(body='', extra='', scope_type='vsys', name='vsys1'):
    return ET.fromstring(
        f'<config><devices><entry name="localhost.localdomain"><{scope_type}>'
        f'<entry name="{name}">{body}</entry>{extra}'
        f'</{scope_type}></entry></devices></config>'
    )


def rule(name='allow', field='source', value='used', rulebase='rulebase'):
    return (f'<{rulebase}><security><rules><entry name="{name}">'
            f'<{field}><member>{value}</member></{field}>'
            f'</entry></rules></security></{rulebase}>')


class AnalysisTests(unittest.TestCase):
    def test_supplied_lab_unused_objects_and_dependency_order(self):
        plan = cleanup.analyze(ET.parse(FIXTURE).getroot())
        self.assertEqual(len(plan.objects), 21)
        self.assertEqual({key.name for key in plan.deleting}, {
            'SRV-ADMIN', 'NET-OLD', 'TAG-OLD', 'UDP-54', 'GRP-OLD',
            'SG-OLD', 'SRV-OLD01', 'SRV-OLD02', 'TCP-8080-OLD',
        })
        self.assertEqual({key.name for key in plan.layers[1]},
                         {'SRV-OLD01', 'SRV-OLD02', 'TCP-8080-OLD'})
        self.assertEqual(plan.rules, [])

    def test_delete_all_in_supplied_lab(self):
        plan = cleanup.analyze(ET.parse(FIXTURE).getroot(), delete_all=True)
        self.assertEqual(len(plan.rules), 5)
        self.assertEqual(len(plan.deleting), 21)
        self.assertEqual(plan.paths[:5], plan.rules)

    def test_same_name_in_address_service_and_tag_namespaces(self):
        body = ('<address><entry name="same"/></address>'
                '<service><entry name="same"/></service>'
                '<tag><entry name="same"/></tag>')
        for field, kept_type in [('source', 'address'), ('destination', 'address'),
                                 ('service', 'service'), ('tag', 'tag')]:
            with self.subTest(field=field):
                plan = cleanup.analyze(config(body + rule(field=field, value='same')))
                self.assertEqual(len(plan.objects), 3)
                self.assertEqual(set(plan.objects) - plan.deleting, {Key(kept_type, 'same')})

    def test_service_group_does_not_use_same_named_address(self):
        body = ('<address><entry name="same"/></address>'
                '<service><entry name="same"/></service>'
                '<service-group><entry name="group"><members><member>same</member>'
                '</members></entry></service-group>')
        plan = cleanup.analyze(config(body + rule(field='service', value='group')))
        self.assertEqual(plan.deleting, {Key('address', 'same')})

    def test_nested_groups_are_deleted_before_their_members(self):
        cfg = config('<address><entry name="leaf"/></address><address-group>'
                     '<entry name="inner"><static><member>leaf</member></static></entry>'
                     '<entry name="outer"><static><member>inner</member></static></entry>'
                     '</address-group>')
        self.assertEqual(cleanup.analyze(cfg).layers, [
            [Key('address-group', 'outer')], [Key('address-group', 'inner')],
            [Key('address', 'leaf')],
        ])
        self.assertEqual(cleanup.analyze(cfg, keep=['outer']).deleting, set())

    def test_keep_applies_to_all_types_with_that_name(self):
        cfg = config('<address><entry name="same"/></address><service><entry name="same"/></service>')
        self.assertEqual(cleanup.analyze(cfg, keep=['same'], delete_all=True).deleting, set())
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            cleanup.analyze(cfg, keep=['typo'])

    def test_rule_outside_selected_vsys_remains_a_dependency_in_delete_all(self):
        extra = '<entry name="vsys2">' + rule() + '</entry>'
        cfg = config('<address><entry name="used"/></address>' + rule(), extra)
        plan = cleanup.analyze(cfg, delete_all=True)
        self.assertEqual(len(plan.rules), 1)
        self.assertIn("vsys1", plan.rules[0])
        self.assertEqual(plan.deleting, set())
        reasons = plan.users[Key('address', 'used')]
        self.assertTrue(any('vsys2' in reason for reason in reasons))

    def test_panorama_pre_and_post_rules_and_other_device_group(self):
        extra = '<entry name="parent">' + rule(rulebase='pre-rulebase') + '</entry>'
        cfg = config('<address><entry name="used"/></address>'
                     + rule(rulebase='pre-rulebase') + rule(rulebase='post-rulebase'),
                     extra, 'device-group', 'lab')
        plan = cleanup.analyze(cfg, device_group='lab', delete_all=True)
        self.assertEqual(len(plan.rules), 2)
        self.assertTrue(all("entry[@name='lab']" in path for path in plan.rules))
        self.assertEqual(plan.deleting, set())

    def test_unknown_external_reference_is_conservatively_kept(self):
        cfg = config('<address><entry name="used"/></address><unknown><value>used</value></unknown>')
        self.assertEqual(cleanup.analyze(cfg).deleting, set())

    def test_description_is_not_a_reference(self):
        cfg = config('<address><entry name="unused"/></address><description>unused</description>')
        self.assertEqual(cleanup.analyze(cfg).deleting, {Key('address', 'unused')})

    def test_dynamic_group_with_negative_filter_keeps_untagged_addresses(self):
        cfg = config('<address><entry name="untagged"/></address>'
                     '<tag><entry name="blocked"/></tag><address-group><entry name="dynamic">'
                     '<dynamic><filter>not \'blocked\'</filter></dynamic></entry></address-group>'
                     + rule(value='dynamic'))
        self.assertEqual(cleanup.analyze(cfg).deleting, set())

    def test_unused_dynamic_group_can_release_addresses_and_double_quoted_tags(self):
        cfg = config('<address><entry name="leaf"/></address><tag><entry name="lab"/></tag>'
                     '<address-group><entry name="dynamic"><dynamic><filter>"lab"</filter>'
                     '</dynamic></entry></address-group>')
        plan = cleanup.analyze(cfg)
        self.assertEqual(plan.layers[0], [Key('address-group', 'dynamic')])
        self.assertEqual(len(plan.deleting), 3)

    def test_dependency_cycle_is_kept(self):
        cfg = config('<address-group><entry name="a"><static><member>b</member></static></entry>'
                     '<entry name="b"><static><member>a</member></static></entry></address-group>')
        self.assertEqual(cleanup.analyze(cfg).deleting, set())

    def test_missing_or_ambiguous_scope_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'found 0'):
            cleanup.analyze(config(), vsys='missing')
        with self.assertRaisesRegex(ValueError, 'found 2'):
            cleanup.analyze(config(extra='<entry name="vsys1"/>'))

    def test_duplicate_same_type_object_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate object'):
            cleanup.analyze(config('<address><entry name="x"/><entry name="x"/></address>'))

    def test_response_wrappers_and_missing_config(self):
        cfg = config()
        for tag in ('result', 'response'):
            wrapper = ET.Element(tag)
            wrapper.append(cfg)
            self.assertIs(cleanup.config_element(wrapper), cfg)
        for root in (None, ET.fromstring('<response><result/></response>')):
            with self.assertRaises(ValueError):
                cleanup.config_element(root)

    def test_xpath_quotes_are_not_interpolated_unsafely(self):
        self.assertEqual(cleanup.xpath_literal("lab's"), '"lab\'s"')
        with self.assertRaises(ValueError):
            cleanup.xpath_literal('both\'"')
        cfg = config('<address><entry name="lab&apos;s"/></address>')
        self.assertIn('[@name="lab\'s"]', cleanup.analyze(cfg).paths[0])


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.enterContext(contextlib.redirect_stderr(self.errors))
        self.api = Mock()
        self.api.timeout = 60
        self.cfg = config('<address><entry name="unused"/></address>')
        self.api.element_result = self.cfg
        self.enterContext(patch.object(cleanup, 'connect', return_value=self.api))
        self.args = ['--host', 'lab.test', '--backup-dir', self.temp.name]

    def test_offline_cli_exports_plan_without_connecting(self):
        path = Path(self.temp.name) / 'lab.plan.json'
        self.assertEqual(cleanup.main(['--config', str(FIXTURE), '--plan-file', str(path)]), 0)
        cleanup.connect.assert_not_called()
        data = json.loads(path.read_text())
        self.assertEqual(sum(map(len, data['object_layers'])), 9)
        self.assertEqual(len(data['kept']), 12)
        self.assertEqual(len(data['config_sha256']), 64)
        self.assertIn('DRY RUN', self.output.getvalue())

    def test_invalid_cli_combinations_are_rejected(self):
        for args in (['--config', str(FIXTURE), '--apply'],
                     ['--host', 'lab', '--commit'], ['--host', 'lab', '--timeout', '0']):
            with self.subTest(args=args), self.assertRaises(SystemExit) as exc:
                cleanup.main(args)
            self.assertEqual(exc.exception.code, 2)
        cleanup.connect.assert_not_called()

    def test_dry_run_backs_up_and_never_mutates(self):
        with patch('builtins.input') as confirmation:
            self.assertEqual(cleanup.main(self.args), 0)
        confirmation.assert_not_called()
        self.api.delete.assert_not_called()
        self.api.commit.assert_not_called()
        self.api.get.assert_called_once_with('/config')
        backups = list(Path(self.temp.name).glob('backup-*.xml'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(ET.parse(backups[0]).getroot().tag, 'config')
        if os.name == 'posix':
            self.assertEqual(backups[0].stat().st_mode & 0o077, 0)

    def test_wrong_confirmation_cancels_without_deletes(self):
        with patch('builtins.input', return_value='wrong'):
            self.assertEqual(cleanup.main(self.args + ['--apply']), 0)
        self.api.delete.assert_not_called()
        self.api.commit.assert_not_called()
        self.assertEqual(self.api.get.call_count, 1)

    def test_confirmed_apply_rechecks_and_changes_candidate_only(self):
        with patch('builtins.input', return_value='lab.test/vsys1'):
            self.assertEqual(cleanup.main(self.args + ['--apply']), 0)
        self.assertEqual(self.api.get.call_count, 2)
        self.api.delete.assert_called_once_with(cleanup.analyze(self.cfg).paths[0])
        self.api.commit.assert_not_called()

    def test_changed_candidate_aborts_before_first_delete(self):
        changed = config('<address><entry name="new"/></address>')
        def get_config(_):
            self.api.element_result = self.cfg if self.api.get.call_count == 1 else changed
        self.api.get.side_effect = get_config
        with patch('builtins.input', return_value='lab.test/vsys1'):
            self.assertEqual(cleanup.main(self.args + ['--apply']), 1)
        self.assertIn('changed after planning', self.errors.getvalue())
        self.api.delete.assert_not_called()
        self.api.commit.assert_not_called()

    def test_backup_failure_prevents_any_mutation(self):
        with patch.object(cleanup, 'write_private', side_effect=OSError('disk full')):
            self.assertEqual(cleanup.main(self.args + ['--apply']), 1)
        self.api.delete.assert_not_called()
        self.api.commit.assert_not_called()

    def test_no_objects_does_not_prompt_or_commit(self):
        self.api.element_result = config()
        with patch('builtins.input') as confirmation:
            self.assertEqual(cleanup.main(self.args + ['--apply', '--commit']), 0)
        confirmation.assert_not_called()
        self.api.commit.assert_not_called()

    def test_failed_delete_stops_and_suppresses_commit(self):
        plan = cleanup.analyze(config('<address><entry name="a"/><entry name="b"/><entry name="c"/></address>'))
        self.api.delete.side_effect = [None, cleanup.PanXapiError('failed')]
        with self.assertRaisesRegex(RuntimeError, '1/3 confirmed deletions'):
            cleanup.apply_plan(self.api, plan, commit=True)
        self.assertEqual(self.api.delete.call_count, 2)
        self.api.commit.assert_not_called()

    def test_successful_commit_requires_ok_job(self):
        plan = cleanup.analyze(self.cfg)
        self.api.element_result = ET.fromstring('<result><job><status>FIN</status><result>OK</result></job></result>')
        cleanup.apply_plan(self.api, plan, commit=True)
        self.api.commit.assert_called_once_with(cmd='<commit></commit>', sync=True, timeout=60)
        self.assertIn('Commit completed successfully', self.output.getvalue())

    def test_commit_fail_or_unknown_result_is_not_reported_as_success(self):
        for result in ('FAIL', ''):
            self.api.element_result = ET.fromstring(f'<result><job><result>{result}</result></job></result>')
            with self.subTest(result=result), self.assertRaisesRegex(RuntimeError, 'commit failed'):
                cleanup.apply_plan(self.api, cleanup.analyze(self.cfg), commit=True)
        self.assertNotIn('Commit completed successfully', self.output.getvalue())

    def test_existing_plan_is_not_overwritten(self):
        path = Path(self.temp.name) / 'existing.plan.json'
        path.write_text('existing data')
        self.assertEqual(cleanup.main(['--config', str(FIXTURE), '--plan-file', str(path)]), 1)
        self.assertEqual(path.read_text(), 'existing data')

    def test_api_errors_do_not_print_request_secrets(self):
        self.api.get.side_effect = cleanup.PanXapiError('fake-password-in-request')
        self.assertEqual(cleanup.main(self.args), 1)
        self.assertNotIn('fake-password-in-request', self.errors.getvalue())
        self.assertIn('Device API request failed', self.errors.getvalue())

    def test_invalid_xml_reports_an_error(self):
        path = Path(self.temp.name) / 'bad.xml'
        path.write_text('<config>')
        self.assertEqual(cleanup.main(['--config', str(path)]), 1)
        cleanup.connect.assert_not_called()


class ConnectionTests(unittest.TestCase):
    def test_api_key_uses_verified_tls_without_password_prompt(self):
        args = cleanup.parse_args(['--host', 'lab.test'])
        with patch.dict(os.environ, {'PAN_API_KEY': 'fake-key'}, clear=True), \
                patch.object(cleanup, 'PanXapi') as constructor, \
                patch.object(cleanup.getpass, 'getpass') as prompt:
            cleanup.connect(args)
        options = constructor.call_args.kwargs
        self.assertEqual(options['api_key'], 'fake-key')
        self.assertIsNone(options['api_password'])
        self.assertEqual(options['ssl_context'].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(options['ssl_context'].check_hostname)
        prompt.assert_not_called()

    def test_password_comes_from_environment_without_prompt(self):
        args = cleanup.parse_args(['--host', 'lab.test', '--user', 'admin'])
        with patch.dict(os.environ, {'PAN_PASSWORD': 'fake-password'}, clear=True), \
                patch.object(cleanup, 'PanXapi') as constructor, \
                patch.object(cleanup.getpass, 'getpass') as prompt:
            cleanup.connect(args)
        self.assertEqual(constructor.call_args.kwargs['api_password'], 'fake-password')
        prompt.assert_not_called()

    def test_password_can_be_entered_without_editing_source(self):
        args = cleanup.parse_args(['--host', 'lab.test', '--user', 'admin'])
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(cleanup, 'PanXapi') as constructor, \
                patch.object(cleanup.getpass, 'getpass', return_value='fake-password'):
            cleanup.connect(args)
        self.assertEqual(constructor.call_args.kwargs['api_password'], 'fake-password')


class SdkIntegrationTests(unittest.TestCase):
    def test_real_sdk_parses_config_and_runs_delete_commit_protocol(self):
        cfg = config('<address><entry name="unused"/></address>')
        messages = [
            b'<response status="success"><result>' + ET.tostring(cfg) + b'</result></response>',
            b'<response status="success" code="20"><msg>command succeeded</msg></response>',
            b'<response status="success"><result><job>1</job></result></response>',
            b'<response status="success"><result><job><status>FIN</status><result>OK</result></job></result></response>',
        ]
        responses = []
        for message in messages:
            response = Mock()
            response.read.return_value = message
            response.getheader.return_value = 'application/xml; charset=utf-8'
            responses.append(response)
        api = cleanup.PanXapi(hostname='lab.test', api_key='fake-key', timeout=60,
                              ssl_context=ssl.create_default_context())
        with patch('pan.xapi.urlopen', side_effect=responses) as request, \
                patch('pan.xapi.time.sleep'), contextlib.redirect_stdout(io.StringIO()):
            plan = cleanup.analyze(cleanup.read_device_config(api))
            cleanup.apply_plan(api, plan, commit=True)
        queries = [parse_qs(call.kwargs['url'].data.decode()) for call in request.call_args_list]
        self.assertEqual([query['type'][0] for query in queries], ['config', 'config', 'commit', 'op'])
        self.assertEqual(queries[0]['action'], ['get'])
        self.assertEqual(queries[1]['action'], ['delete'])
        self.assertEqual(queries[1]['xpath'], plan.paths)
        for call in request.call_args_list:
            self.assertEqual(call.kwargs['context'].verify_mode, ssl.CERT_REQUIRED)


if __name__ == '__main__':
    unittest.main()
