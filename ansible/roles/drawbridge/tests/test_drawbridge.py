import os
import pytest
import testinfra
#import testinfra.utils.ansible_runner
#from ansible.template import Templar
#from ansible.parsing.dataloader import DataLoader

#runner = testinfra.utils.ansible_runner.AnsibleRunner(
#    os.environ['MOLECULE_INVENTORY_FILE']
#)
#testinfra = runner.get_hosts('all')


@pytest.fixture(scope='module')
def get_vars(host):
	defaults_files = "file=./roles/drawbridge/defaults/main.yml name=role_defaults"
	vars_files = "file=./roles/drawbridge/vars/main.yml name=role_vars"

	ansible_vars = host.ansible(
		"include_vars",
		defaults_files)["ansible_facts"]["role_defaults"]

	ansible_vars.update(host.ansible(
		"include_vars",
		vars_files)["ansible_facts"]["role_vars"])

	return ansible_vars

def test_drawbridge_install(host):
	lsmod = host.check_output("lsmod")
	assert "drawbridge" in lsmod


def test_ports_closed(host, get_vars):
	print(get_vars)
	assert "DRAWBRIDGE_PORTS" in get_vars

	localhost = host.addr("127.0.0.1")
	assert localhost.is_resolvable

	for i in get_vars['DRAWBRIDGE_PORTS'].split(','):
		assert localhost.port(i).is_reachable is False

def test_apt_cleanup(host):
	make = host.package("make")
	pip = host.package("python3-pip")
	pkg_resources = host.package("python3-pkg-resources")

	assert make.is_installed is False
	assert pip.is_installed is False
	assert pkg_resources.is_installed is False

'''
def test_key_file(host):
	f = host.file('~/drawbridge/')

	assert f.exists
	assert f.user == 'root'
	assert f.group == 'root'
'''
