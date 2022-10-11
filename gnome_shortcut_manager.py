#!/usr/bin/python3

import argparse
import dataclasses
import datetime
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
from _socket import gethostname
from datetime import datetime
from os import getlogin

import yaml

GSM_VERSION = "0.1-alpha"

log = logging.getLogger(__name__)

###########################################################
#                          LOGS                           #
###########################################################
# from global_resources import LOGS_DIR
LOGS_DIR = "/tmp/gnome_shortcut_manager_logs/"

# log = logging.getLogger(__name__)
#
# log: logging = None

LOG_FILE_PREFIX = "gsm-"

LOG_FILE_FORMAT = "%(asctime)s [%(filename)20s:%(funcName)20s():%(lineno)s] " \
                  "[%(levelname)-s]:\t %(message)s"
LOG_STDOUT_FORMAT = "|%(levelname)s|: %(message)s"

loglevel_map = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
    "critical": 50,
}


def init_logger(loglevel, verbose=False):
    global log

    if verbose is True:
        loglevel = "debug"
    elif loglevel is None:
        loglevel = "info"

    print("Current console loglevel is: %s" % loglevel)

    console_loglevel = loglevel_map.get(loglevel)
    if console_loglevel is None:
        print("Invalid loglevel: \"%s\"" % loglevel)
        sys.exit()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # prepare log file
    pathlib.Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)

    timestamp = str(datetime.now()).split('.')[0].replace(' ', '_')
    log_file_name = LOG_FILE_PREFIX + timestamp + ".log"

    # setup logs to file
    log_file_format = logging.Formatter(LOG_FILE_FORMAT,
                                        datefmt='%Y-%m-%d %H:%M:%S')

    file_handler = logging.FileHandler(LOGS_DIR + log_file_name)
    file_handler.setFormatter(log_file_format)
    file_handler.setLevel(logging.DEBUG)

    root_logger.addHandler(file_handler)

    # setup logs to stdout
    log_stdout_format = logging.Formatter(LOG_STDOUT_FORMAT)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_stdout_format)
    console_handler.setLevel(console_loglevel)

    root_logger.addHandler(console_handler)

    log = root_logger


def get_logger():
    global log
    return log


###########################################################
#                          CORE                           #
###########################################################
# defining keys & strings to be used
custom_keybind_scheme = "org.gnome.settings-daemon.plugins.media-keys.custom-keybinding"
media_keys_scheme = "org.gnome.settings-daemon.plugins.media-keys"
custom_keybind_key = "custom-keybindings"
custom_keybind_path = custom_keybind_scheme + ":/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/"


def get(cmd):
    log.debug("Executing: " + cmd)
    return subprocess.check_output(["/bin/bash", "-c", cmd]).decode("utf-8")


def run(cmd):
    log.debug("Executing: " + cmd)
    subprocess.call(["/bin/bash", "-c", cmd])


@dataclasses.dataclass
class Shortcut:
    name: str
    command: str
    binding: str
    node: str


def get_shortcut_from_node(node: str):
    scheme_and_path = custom_keybind_path + node

    def get_property(shortcut_key):
        return get("gsettings get %s/ %s" % (scheme_and_path, shortcut_key)).replace("\n", "").lstrip("'").rstrip("'")

    name = get_property("name")
    command = get_property("command")
    binding = get_property("binding")

    log.info("""Found shortcut with:
    node: %s
    name: %s
    command: %s
    binding: %s
    """ % (node, name, command, binding))

    return Shortcut(name, command, binding, node)


def get_current_shortcut_node_path_list():
    array_str = get("gsettings get %s %s" % (media_keys_scheme, custom_keybind_key))

    # in case the array was empty, remove the annotation hints
    command_result = array_str.lstrip("@as")
    current = eval(command_result)  # Make array from array string

    if type(current) is not list:
        Exception("Result is not list")

    log.debug("Raw array:\n%s" % "\n".join(current))

    return current


def get_registered_shortcuts():
    current = get_current_shortcut_node_path_list()

    shortcuts = []
    for path in current:
        shortcuts.append(get_shortcut_from_node(path.split("/")[-2]))

    log.debug(shortcuts)
    return shortcuts


def make_gsm_config_from_shortcuts(shortcuts):
    data = {
        "gsm-version": GSM_VERSION,
        "description": "Gnome shortcuts dumped form %s@%s at %s" % (getlogin(), gethostname(), datetime.now())
    }
    plain_shortcuts = []

    for shortcut in shortcuts:
        plain_shortcuts.append(
            {
                "node": shortcut.node,
                "name": shortcut.name,
                "command": shortcut.command,
                "binding": shortcut.binding
            }
        )
    data["shortcuts"] = plain_shortcuts

    return data


def export_shortcuts_to_config_data():
    shortcuts = get_registered_shortcuts()
    return make_gsm_config_from_shortcuts(shortcuts)


def config_data_to_yaml(data):
    yaml_str = yaml.dump(data, indent=4, sort_keys=False)
    log.debug("Result yaml:\n" + yaml_str)
    return yaml_str


def config_data_to_json(data):
    json_str = json.dumps(data, indent=4)
    log.debug("Result json:\n" + json_str)
    return json_str


def map_config_data(data: dict):
    shortcuts_dict = data["shortcuts"]
    shortcuts = []

    shortcut: dict
    for shortcut in shortcuts_dict:
        shortcuts.append(
            Shortcut(
                name=shortcut["name"],
                command=shortcut["command"],
                binding=shortcut["binding"],
                node=shortcut["node"]
            )
        )

    log.debug("Got shortcuts from config:" % shortcuts)
    return shortcuts


def apply_shortcut(shortcut):
    if re.match("custom?[0-9]", shortcut.node) is None:
        Exception("Not valid node: %s. Node should match 'custom0' example" % shortcut.node)

    scheme_and_path = custom_keybind_path + shortcut.node

    def set_property(key, value):
        run("gsettings set %s/ %s '%s'" % (scheme_and_path, key, value))

    set_property("name", shortcut.name)
    set_property("command", shortcut.command)
    set_property("binding", shortcut.binding)


def apply_shortcuts_from_array(shortcuts):
    for shortcut in shortcuts:
        log.info("""Applying shortcut with:
        node: %s
        name: %s
        command: %s
        binding: %s
        """ % (shortcut.node, shortcut.name, shortcut.command, shortcut.binding))
        apply_shortcut(shortcut)


def apply_shortcuts_from_config(data):
    if data["gsm-version"] != GSM_VERSION:
        log.warning("Version missmatch: config version: %s, GSM version: %s" % (data["version"], GSM_VERSION))

    shortcuts = map_config_data(data)

    apply_shortcuts_from_array(shortcuts)


###########################################################
#                          MAIN                           #
###########################################################
def parse_args():
    usage_message = """
    This is Gnome custom shortcut manager.
    You can export or import yor custom shortcuts from/to file

    """

    # option properties
    export_sh_arg = {"action": "store_true", "help": "Export existing shortcuts from system to file (yaml/json)"}
    import_sh_arg = {"action": "store_true", "help": "Import existing shortcuts from file (yaml/json) to system"}

    file_arg = {"metavar": 'FILE', "help": "Path to the file to load/store shortcuts from"}
    config_type_arg = {"choices": ["yaml", "json"], "help": "Override config file extension"}
    verbose_arg = {"action": "store_true", "help": "Use verbose mode"}

    opt_parser = argparse.ArgumentParser(usage_message)
    direction = opt_parser.add_mutually_exclusive_group(required=True)
    direction.add_argument('-e', '--export-shortcuts', **export_sh_arg)
    direction.add_argument('-a', '--apply-shortcuts', **import_sh_arg)
    opt_parser.add_argument('-f', '--file', **file_arg)
    opt_parser.add_argument('-t', '--config-type', **config_type_arg)
    opt_parser.add_argument('-v', '--verbose', **verbose_arg)

    options = opt_parser.parse_args()

    return options


def get_filetype(options):
    if options.config_type is not None:
        return options.config_type

    resolution: str = options.file.split(".")[-1]
    if resolution.lower() == "yaml":
        log.info("Filetype is yaml")
        return "yaml"
    elif resolution.lower() == "json":
        log.info("Filetype is json")
        return "json"
    else:
        Exception("No config type (yaml/json) was provided, and config type can't be guessed form file resolution")


def export_shortcuts_to_file(options, file_path):
    filetype = get_filetype(options)

    if os.path.isfile(file_path):
        print("File %s already exists do you want to override it? (y/n): " % file_path, end="")
        response = input()
        if response != "y":
            print("Aborting...")
            sys.exit()

    data = export_shortcuts_to_config_data()

    if not os.path.exists(file_path):
        os.mknod(file_path, 0o644)

    buffer = ""
    if filetype == "yaml":
        buffer = config_data_to_yaml(data)
    elif filetype == "json":
        buffer = config_data_to_json(data)

    file = open(file_path, "w")
    file.write(buffer)
    file.close()


def backup_shortcuts(options):
    backup_file = options.file + ".system.bak"
    print("Backing up existing shortcuts to %s." % backup_file)
    export_shortcuts_to_file(options, backup_file)


def apply_shortcuts_from_file(options):
    if not os.path.exists(options.file):
        print("File %s does not exist" % options.file)
        return

    backup_shortcuts(options)

    file = open(options.file, "r")
    data_str = file.read()

    data = []
    filetype = get_filetype(options)
    if filetype == "yaml":
        data = yaml.safe_load(data_str)
    elif filetype == "json":
        data = json.loads(data_str)
    else:
        Exception("Wrong file resolution")

    apply_shortcuts_from_config(data)


def main():
    options = parse_args()

    global log
    init_logger("info", options.verbose)
    log = get_logger()

    if options.export_shortcuts is True:
        print("tr")
        export_shortcuts_to_file(options, options.file)
    if options.apply_shortcuts is True:
        apply_shortcuts_from_file(options)


if __name__ == '__main__':
    main()
