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


def test_the_plugin_has_its_two_actions():
    assert actions().sections() == ["status", "flush"]


def test_every_action_is_served_to_wheel_and_wwwonly_alone():
    # configd splits the value at commas and keeps each item as it is, so a space would name another group
    groups = {section: actions().get(section, "allowed_groups", fallback=None) for section in actions().sections()}
    assert groups == {"status": "wheel,wwwonly", "flush": "wheel,wwwonly"}
