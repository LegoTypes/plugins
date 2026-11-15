import configparser
import os

ACTIONS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "opnsense", "service", "conf", "actions.d", "actions_macaliascache.conf",
)


def actions():
    """ the action file as configd reads it: its parser, RawConfigParser, one section per action """
    parser = configparser.RawConfigParser()
    with open(ACTIONS, encoding="utf-8") as fh:
        parser.read_file(fh)
    return parser


SCRIPT = "/usr/local/opnsense/scripts/OPNsense/MacAliasCache/macalias.py"


def test_the_plugin_has_its_three_actions():
    assert actions().sections() == ["status", "flush", "neighbors"]


def test_every_action_is_served_to_wheel_and_wwwonly_alone():
    # configd splits the value at commas and keeps each item as it is, so a space would name another group
    groups = {section: actions().get(section, "allowed_groups", fallback=None) for section in actions().sections()}
    assert groups == {"status": "wheel,wwwonly", "flush": "wheel,wwwonly", "neighbors": "wheel,wwwonly"}


def test_every_action_runs_the_one_script_and_answers_its_json():
    parser = actions()
    for section in parser.sections():
        assert parser.get(section, "command") == "%s %s" % (SCRIPT, section)
        assert parser.get(section, "parameters") == ""
        assert parser.get(section, "type") == "script_output"


def test_no_action_is_offered_as_a_scheduled_job():
    # core lists an action that has a description under System: Settings: Cron and runs such a job as nobody, whom
    # allowed_groups refuses; the neighbor tick's minute job is the package's own cron.d file
    for section in actions().sections():
        assert not actions().has_option(section, "description"), section
