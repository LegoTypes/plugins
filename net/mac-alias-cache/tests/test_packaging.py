import os
import pathlib
import re
import stat
import subprocess
import xml.etree.ElementTree as ET

import pytest

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
    # the saved value, and the model's default of 0 both for a node that is missing and for one that is empty
    assert text_of(TEMPLATES, "macaliascache.conf") == (
        "[general]\n"
        "{% if helpers.exists('OPNsense.MacAliasCache.general.neighbors') %}\n"
        "neighbors={{ OPNsense.MacAliasCache.general.neighbors|default('0', true) }}\n"
        "{% else %}\n"
        "neighbors=0\n"
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
        chosen = lines[2].replace("{{ OPNsense.MacAliasCache.general.neighbors|default('0', true) }}", value or "0")
    return "%s\n%s\n" % (lines[0], chosen)


def test_what_the_template_renders_is_what_the_script_parses():
    assert rendered("0") == rendered("") == rendered(None) == "[general]\nneighbors=0\n"
    assert rendered("1") == "[general]\nneighbors=1\n"
    assert lib.parse_setting(rendered("1")) is True
    assert lib.parse_setting(rendered("0")) is False
    assert lib.parse_setting(rendered(None)) is False


def test_the_model_holds_the_one_setting_off_by_default():
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
    # off: an upgrade changes no alias until the administrator turns the setting on, and a file that was never
    # rendered reads the same
    assert {child.tag: child.text for child in field} == {"Default": "0", "Required": "Y"}
    assert macalias.read_setting(dict(macalias.DEFAULTS, settings_file=os.path.join(PLUGIN, "no-such-file"))) == (
        False, "absent")
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
    steps = ["$this->request->isPost()", "$this->throwReadOnly();",
             "configdRun('template reload OPNsense/MacAliasCache')", "!== 'OK'",
             "configdRun('macaliascache neighbors')"]
    positions = [body.index(step) for step in steps]
    assert positions == sorted(positions)
    assert body.count("return ['status' => 'failed'];") == 2
    assert "'status' => 'ok'" in body
    # the flush keeps its own guard
    flush = service.split("public function flushAction()", 1)[1].split("\n    }\n", 1)[0]
    assert "$this->throwReadOnly();" in flush


def hook(name):
    return text_of(PLUGIN, name)


SCRIPTS_DIR = os.path.dirname(SCRIPT)
BUSY = '{"error": "busy", "detail": "alias update lock held for 5.0s"}'
REMOVED = '{"result": "ok", "changed": true, "added": 0, "removed": 2, "refreshed": 0, "keys": 0, "over_limit": 0, ' \
    '"samples": []}'
REFUSED = '{"error": "core_changed", "detail": "core changed"}'


def run_hook(name, tmp_path, env=None):
    """ the package script name run by sh as pkg runs it, with every path of the box it names pointed into
    tmp_path, and a sleep of the harness's own first on PATH that records its arguments and returns at once
    """
    for path in (SCRIPT, SCRIPTS_DIR, SETTINGS_FILE):
        assert path.startswith("/usr/local/")
    assert STATE_DIR.startswith("/var/run/") and "/usr/local/" not in str(tmp_path) and "/var/run/" not in str(tmp_path)
    text = hook(name).replace("/var/run/", "%s/var/run/" % tmp_path).replace("/usr/local/", "%s/usr/local/" % tmp_path)
    script = tmp_path / "hook.sh"
    script.write_text(text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    sleeper = bin_dir / "sleep"
    sleeper.write_text('#!/bin/sh\necho "$@" >> "%s/sleeps"\n' % tmp_path)
    sleeper.chmod(0o755)
    run_env = {"PATH": "%s:/bin:/usr/bin" % bin_dir}
    run_env.update(env or {})
    proc = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True, env=run_env, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def fake_removal(tmp_path, replies, executable=True):
    """ a macalias.py at the installed path under tmp_path that records its arguments and prints the next of
    replies on each call, nothing once they are used up
    """
    script = pathlib.Path(str(tmp_path) + SCRIPT)
    script.parent.mkdir(parents=True)
    pathlib.Path(str(tmp_path) + os.path.dirname(SETTINGS_FILE)).mkdir(parents=True)
    for number, reply in enumerate(replies, 1):
        (tmp_path / ("reply.%d" % number)).write_text(reply + "\n")
    script.write_text(
        '#!/bin/sh\necho "$@" >> "%s/calls"\nn=$(grep -c . "%s/calls")\n'
        '[ -f "%s/reply.$n" ] && cat "%s/reply.$n"\nexit 0\n' % ((tmp_path,) * 4))
    script.chmod(0o755 if executable else 0o644)


def lines_of(tmp_path, name):
    path = tmp_path / name
    return path.read_text().splitlines() if path.exists() else []


def setting_written(tmp_path):
    path = pathlib.Path(str(tmp_path) + SETTINGS_FILE)
    return path.read_text() if path.exists() else None


def test_a_real_removal_takes_the_keys_out_of_cores_cache_and_an_upgrade_keeps_them(tmp_path):
    assert hook("+PRE_DEINSTALL.pre").startswith("#!/bin/sh\n")
    fake_removal(tmp_path, [REMOVED])
    assert run_hook("+PRE_DEINSTALL.pre", tmp_path) == ""
    # the setting is off in the rendered file, so a tick of cron's that starts meanwhile removes too
    assert setting_written(tmp_path) == "[general]\nneighbors=0\n"
    assert lib.parse_setting(setting_written(tmp_path)) is False
    assert lines_of(tmp_path, "calls") == ["neighbors remove"]
    assert lines_of(tmp_path, "sleeps") == []


@pytest.mark.parametrize("content", ["[general]\nneighbors=1\n", "[general]\nneighbors=0\n", "neighbors on\n"],
                         ids=["on", "off", "unusable"])
def test_a_removal_turns_the_setting_off_in_the_rendered_file_whatever_it_held(tmp_path, content):
    fake_removal(tmp_path, [REMOVED])
    pathlib.Path(str(tmp_path) + SETTINGS_FILE).write_text(content)
    assert run_hook("+PRE_DEINSTALL.pre", tmp_path) == ""
    assert setting_written(tmp_path) == "[general]\nneighbors=0\n"


def test_an_upgrade_runs_no_removal(tmp_path):
    fake_removal(tmp_path, [REMOVED])
    assert run_hook("+PRE_DEINSTALL.pre", tmp_path, {"PKG_UPGRADE": "1"}) == ""
    assert lines_of(tmp_path, "calls") == [] and setting_written(tmp_path) is None


def test_a_removal_without_the_script_does_nothing(tmp_path):
    fake_removal(tmp_path, [REMOVED], executable=False)
    assert run_hook("+PRE_DEINSTALL.pre", tmp_path) == ""
    assert lines_of(tmp_path, "calls") == [] and setting_written(tmp_path) is None


def test_the_removal_asks_again_while_the_answer_is_busy(tmp_path):
    # core's own alias update can hold its lock for longer than the removal waits for it
    fake_removal(tmp_path, [BUSY, BUSY, REMOVED])
    assert run_hook("+PRE_DEINSTALL.pre", tmp_path) == ""
    assert lines_of(tmp_path, "calls") == ["neighbors remove"] * 3
    assert lines_of(tmp_path, "sleeps") == ["2", "2"]


def test_a_removal_that_stays_busy_gives_up_with_one_line_and_no_last_sleep(tmp_path):
    fake_removal(tmp_path, [BUSY] * 6)
    out = run_hook("+PRE_DEINSTALL.pre", tmp_path)
    assert lines_of(tmp_path, "calls") == ["neighbors remove"] * 3
    assert lines_of(tmp_path, "sleeps") == ["2", "2"]
    assert out.splitlines() == [
        "os-mac-alias-cache: the plugin's keys were not removed from core's MAC alias cache and expire there within "
        "12 hours: " + BUSY]


def test_a_removal_that_is_refused_or_answers_nothing_says_so_in_one_line(tmp_path):
    fake_removal(tmp_path, [REFUSED])
    out = run_hook("+PRE_DEINSTALL.pre", tmp_path)
    assert lines_of(tmp_path, "calls") == ["neighbors remove"] and lines_of(tmp_path, "sleeps") == []
    assert out.splitlines() == [
        "os-mac-alias-cache: the plugin's keys were not removed from core's MAC alias cache and expire there within "
        "12 hours: " + REFUSED]
    (tmp_path / "reply.1").unlink()
    (tmp_path / "calls").unlink()
    out = run_hook("+PRE_DEINSTALL.pre", tmp_path)
    assert out.splitlines() == [
        "os-mac-alias-cache: the plugin's keys were not removed from core's MAC alias cache and expire there within "
        "12 hours: no reply"]


def leftovers(tmp_path):
    """ what the package does not own and a removal must not leave: the rendered settings file, the state
    directory with a record, and the compiled Python root's runs made beside the scripts
    """
    made = [pathlib.Path(str(tmp_path) + SETTINGS_FILE), pathlib.Path(str(tmp_path) + STATE_DIR) / "neighbors.json",
            pathlib.Path(str(tmp_path) + SCRIPTS_DIR) / "__pycache__" / "macaliascache_lib.cpython-311.pyc"]
    for path in made:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
    return [made[0], made[1].parent, made[2].parent, made[2].parent.parent]


def test_a_real_removal_leaves_no_settings_file_no_state_and_no_compiled_python(tmp_path):
    paths = leftovers(tmp_path)
    assert run_hook("+POST_DEINSTALL.post", tmp_path) == ""
    assert [path for path in paths if path.exists()] == []
    assert macalias.DEFAULTS["state_dir"] == STATE_DIR
    # the saved setting is the user's and stays in the configuration
    assert "config.xml" not in hook("+POST_DEINSTALL.post") and "config.xml" not in hook("+PRE_DEINSTALL.pre")


def test_a_removal_leaves_a_scripts_directory_that_holds_something_else(tmp_path):
    paths = leftovers(tmp_path)
    (paths[3] / "kept").write_text("x")
    assert run_hook("+POST_DEINSTALL.post", tmp_path) == ""
    assert [path.name for path in paths if path.exists()] == ["MacAliasCache"]


def test_an_upgrade_keeps_the_settings_file_the_state_and_the_compiled_python(tmp_path):
    paths = leftovers(tmp_path)
    assert run_hook("+POST_DEINSTALL.post", tmp_path, {"PKG_UPGRADE": "1"}) == ""
    assert [path for path in paths if not path.exists()] == []


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
    # the one line the firmware page lists: the ports convention is 70 characters at most, no article first, no
    # full stop last
    assert len(comment) <= 70 and not comment.endswith(".") and comment[0].isupper()
    description = text_of(PLUGIN, "pkg-descr").split("Plugin Changelog\n", 1)[0]
    for words in ("configctl macaliascache flush", "neighbor table", "IPv6 only", "32 addresses", "1024 in all",
                  "90 seconds", "restarts", "12 hours", "update frequency", "off by default", "1 MiB",
                  "about 6,000 entries", "about a minute"):
        assert words in " ".join(description.split()), words
    # what the changelog promises of a firewall with the setting off is what the tick does
    entry = " ".join(text_of(PLUGIN, "pkg-descr").split("\n1.4\n", 1)[1].split("\n1.3\n", 1)[0].split())
    assert ("While the setting is off and the plugin holds nothing in core's cache, which is so where it was never on "
            "and from the run that found no key of its own left after it was turned off, the minute job does nothing "
            "at all: it reads no file of core's, runs no program and takes no lock") in entry
    # the release's entry says the setting is off and where it is turned on
    entry = " ".join(text_of(PLUGIN, "pkg-descr").split("\n1.4\n", 1)[1].split("\n1.3\n", 1)[0].split())
    assert "off by default" in entry and "Firewall > Diagnostics > MAC Alias Cache" in entry
    assert "Add addresses from the neighbor table" in entry
    # pkg-descr is shown as plain text in a narrow column
    assert max(len(line) for line in text_of(PLUGIN, "pkg-descr").splitlines()) <= 80
