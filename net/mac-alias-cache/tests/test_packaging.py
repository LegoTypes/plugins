import os
import re
import stat
import subprocess
import xml.etree.ElementTree as ET

import macalias
import macaliascache_lib as lib

PLUGIN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PLUGIN, "src")
MVC = os.path.join(SRC, "opnsense", "mvc", "app")
TEMPLATES = os.path.join(SRC, "opnsense", "service", "templates", "OPNsense", "MacAliasCache")
SCRIPT = "/usr/local/opnsense/scripts/OPNsense/MacAliasCache/macalias.py"
SETTINGS_FILE = "/usr/local/etc/macaliascache.conf"
STATE_DIR = "/var/run/macaliascache"


def text_of(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def code_lines(text):
    """ the lines of a shell or cron file that are neither empty nor a comment """
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_the_cron_file_runs_the_tick_each_minute_at_second_30_as_root():
    text = text_of(SRC, "etc", "cron.d", "macaliascache")
    assert text.endswith("\n")
    jobs = code_lines(text)
    assert len(jobs) == 1
    # a system crontab line: five time fields, the user, the command, tab-separated as the sibling's is
    schedule, user, command = jobs[0].split("\t")
    assert schedule.split(" ") == ["*", "*", "*", "*", "*"]
    assert user == "root"
    # off core's own minute run, which starts at second 0 and leaves its cache at 0 bytes until it ends
    assert command == "sleep 30 && %s neighbors > /dev/null" % SCRIPT
    # cron takes % as a newline
    assert "%" not in jobs[0]


def test_the_cron_file_installs_where_cron_reads_it_and_the_script_can_be_run():
    assert os.path.isfile(os.path.join(SRC, "etc", "cron.d", "macaliascache"))
    script = os.path.join(SRC, "opnsense", "scripts", "OPNsense", "MacAliasCache", "macalias.py")
    assert SCRIPT == "/usr/local" + script[len(SRC):]
    assert os.stat(script).st_mode & stat.S_IXUSR
    assert text_of(script).startswith("#!/usr/local/bin/python3\n")


def test_the_template_renders_the_settings_file_the_script_reads():
    assert text_of(TEMPLATES, "+TARGETS") == "macaliascache.conf:%s\n" % SETTINGS_FILE
    assert macalias.DEFAULTS["settings_file"] == SETTINGS_FILE
    # the saved value, and the model's default of 1 both for a node that is missing and for one that is empty
    assert text_of(TEMPLATES, "macaliascache.conf") == (
        "[general]\n"
        "{% if helpers.exists('OPNsense.MacAliasCache.general.neighbors') %}\n"
        "neighbors={{ OPNsense.MacAliasCache.general.neighbors|default('1', true) }}\n"
        "{% else %}\n"
        "neighbors=1\n"
        "{% endif %}\n")


def rendered(value):
    """ the template's output for a saved value, or for no node when value is None, as configd renders it
    (trim_blocks: the newline after a block tag is dropped)
    """
    lines = text_of(TEMPLATES, "macaliascache.conf").splitlines()
    assert [lines[1], lines[3], lines[5]] == [
        "{% if helpers.exists('OPNsense.MacAliasCache.general.neighbors') %}", "{% else %}", "{% endif %}"]
    if value is None:
        chosen = lines[4]
    else:
        chosen = lines[2].replace("{{ OPNsense.MacAliasCache.general.neighbors|default('1', true) }}", value or "1")
    return "%s\n%s\n" % (lines[0], chosen)


def test_what_the_template_renders_is_what_the_script_parses():
    assert rendered("1") == rendered("") == rendered(None) == "[general]\nneighbors=1\n"
    assert rendered("0") == "[general]\nneighbors=0\n"
    assert lib.parse_setting(rendered("1")) is True
    assert lib.parse_setting(rendered("0")) is False
    assert lib.parse_setting(rendered(None)) is True


def test_the_model_holds_the_one_setting_on_by_default():
    model = ET.parse(os.path.join(MVC, "models", "OPNsense", "MacAliasCache", "MacAliasCache.xml")).getroot()
    assert model.tag == "model"
    assert model.findtext("mount") == "//OPNsense/MacAliasCache"
    assert model.findtext("version") == "1.0.0"
    items = model.find("items")
    assert [child.tag for child in items] == ["general"]
    assert [child.tag for child in items.find("general")] == ["neighbors"]
    field = items.find("general/neighbors")
    assert field.attrib == {"type": "BooleanField"}
    # a default, so it is required: the template needs no check for an empty value
    assert {child.tag: child.text for child in field} == {"Default": "1", "Required": "Y"}
    # the template reads the node the model mounts
    assert "OPNsense.MacAliasCache.general.neighbors" in text_of(TEMPLATES, "macaliascache.conf")


def test_the_model_class_is_empty_and_the_settings_controller_is_the_base_one():
    model = text_of(MVC, "models", "OPNsense", "MacAliasCache", "MacAliasCache.php")
    assert "namespace OPNsense\\MacAliasCache;\n" in model
    assert re.search(r"class MacAliasCache extends BaseModel\n\{\n\}\n\Z", model)
    settings = text_of(MVC, "controllers", "OPNsense", "MacAliasCache", "Api", "SettingsController.php")
    assert "class SettingsController extends ApiMutableModelControllerBase\n" in settings
    assert "protected static $internalModelName = 'macaliascache';\n" in settings
    assert "protected static $internalModelClass = '\\OPNsense\\MacAliasCache\\MacAliasCache';\n" in settings
    # get and set are the base class's own, read-only guard included
    assert "function" not in settings


def test_the_form_is_the_one_checkbox_with_plain_help():
    form = ET.parse(os.path.join(MVC, "controllers", "OPNsense", "MacAliasCache", "forms", "general.xml")).getroot()
    fields = form.findall("field")
    assert [field.findtext("id") for field in fields] == ["macaliascache.general.neighbors"]
    assert fields[0].findtext("label") == "Add addresses from the neighbor table"
    assert fields[0].findtext("type") == "checkbox"
    text = fields[0].findtext("help")
    # plain text with nothing to escape, and what the limits are
    assert text and not re.search(r"""['"<>&]""", text)
    assert "IPv6" in text and "32" in text and "1024" in text
    assert (lib.NEIGHBOR_MAX_PER_MAC, lib.NEIGHBOR_MAX_TOTAL) == (32, 1024)
    index = text_of(MVC, "controllers", "OPNsense", "MacAliasCache", "IndexController.php")
    assert "$this->view->generalForm = $this->getForm('general');\n" in index


def test_reconfigure_renders_the_file_then_runs_one_tick_and_refuses_a_read_only_user():
    service = text_of(MVC, "controllers", "OPNsense", "MacAliasCache", "Api", "ServiceController.php")
    body = service.split("public function reconfigureAction()", 1)[1].split("\n    }\n", 1)[0]
    steps = ["$this->request->isPost()", "$this->throwReadOnly();", "configdRun('template reload OPNsense/MacAliasCache')",
             "!== 'OK'", "configdRun('macaliascache neighbors')"]
    positions = [body.index(step) for step in steps]
    assert positions == sorted(positions)
    assert body.count("return ['status' => 'failed'];") == 2
    assert "'status' => 'ok'" in body
    # the flush keeps its own guard
    flush = service.split("public function flushAction()", 1)[1].split("\n    }\n", 1)[0]
    assert "$this->throwReadOnly();" in flush


def hook(name):
    return text_of(PLUGIN, name)


def test_a_real_removal_takes_the_keys_out_of_cores_cache_and_an_upgrade_keeps_them():
    text = hook("+PRE_DEINSTALL.pre")
    assert text.startswith("#!/bin/sh\n")
    lines = code_lines(text)
    # everything the hook does is inside the one guard: a real removal, with the script still there
    assert lines[0] == 'if [ -z "${PKG_UPGRADE:-}" ] && [ -x %s ]; then' % SCRIPT
    assert lines[-1] == "fi"
    assert all(line.startswith("    ") for line in lines[1:-1])
    body = "\n".join(lines[1:-1])
    # the setting is turned off in the rendered file first, so a tick of cron's that starts meanwhile removes too
    assert body.index("printf '[general]\\nneighbors=0\\n' > %s" % SETTINGS_FILE) < body.index("neighbors remove")
    assert "%s neighbors remove" % SCRIPT in body
    assert lib.parse_setting("[general]\nneighbors=0\n") is False
    # a package script must not fail the removal
    assert "|| true" in body


def test_a_real_removal_leaves_no_settings_file_and_no_state():
    text = hook("+POST_DEINSTALL.post")
    lines = code_lines(text)
    assert lines == ['if [ -z "${PKG_UPGRADE:-}" ]; then', "    rm -rf %s %s" % (SETTINGS_FILE, STATE_DIR), "fi"]
    assert macalias.DEFAULTS["state_dir"] == STATE_DIR
    # the saved setting is the user's and stays in the configuration
    assert "config.xml" not in text and "config.xml" not in hook("+PRE_DEINSTALL.pre")


def test_the_package_scripts_are_valid_sh():
    for name in ("+PRE_DEINSTALL.pre", "+POST_DEINSTALL.post"):
        proc = subprocess.run(["/bin/sh", "-n", os.path.join(PLUGIN, name)], capture_output=True, text=True)
        assert proc.returncode == 0, (name, proc.stderr)


def test_the_package_has_no_install_script_of_its_own():
    # the package's own steps render the template, restart configd and run the model's migration
    assert sorted(name for name in os.listdir(PLUGIN) if name.startswith("+")) == [
        "+POST_DEINSTALL.post", "+PRE_DEINSTALL.pre"]


def makefile():
    """ the Makefile's variables, as name -> value """
    pairs = re.findall(r"^(PLUGIN_[A-Z_]+)=\s*(.*)$", text_of(PLUGIN, "Makefile"), re.MULTILINE)
    return dict(pairs)


def changelog():
    """ the versions pkg-descr's changelog has an entry for, newest first: each stands alone on a line """
    entries = text_of(PLUGIN, "pkg-descr").split("Plugin Changelog\n================\n", 1)[1]
    return re.findall(r"^(\d+\.\d+(?:_\d+)?)$", entries, re.MULTILINE)


def test_changelog_has_version():
    variables = makefile()
    version = variables["PLUGIN_VERSION"]
    if "PLUGIN_REVISION" in variables:
        version += "_" + variables["PLUGIN_REVISION"]
    # a feature release: the minor version, with no revision
    assert version == "1.4"
    versions = changelog()
    assert versions[0] == version
    assert len(versions) == len(set(versions)) and versions[1] == "1.3"


def test_the_package_describes_both_of_its_functions_and_the_limits():
    comment = makefile()["PLUGIN_COMMENT"]
    assert "neighbor table" in comment and "host discovery" in comment
    description = text_of(PLUGIN, "pkg-descr").split("Plugin Changelog\n", 1)[0]
    for words in ("configctl macaliascache flush", "neighbor table", "IPv6 only", "32 addresses", "1024 in all",
                  "90 seconds", "restarts", "12 hours", "update frequency"):
        assert words in " ".join(description.split()), words
    # pkg-descr is shown as plain text in a narrow column
    assert max(len(line) for line in text_of(PLUGIN, "pkg-descr").splitlines()) <= 80
