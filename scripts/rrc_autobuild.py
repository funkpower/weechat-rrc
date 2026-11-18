# rrc_autobuild.py - rebuild weechat-rrc when a WeeChat upgrade leaves it unloaded
#
# WeeChat loads a C plugin only if it was built against the running WeeChat's
# plugin API, which changes with most WeeChat releases. After an upgrade the old
# rrc.so is refused, and the RRC buffers kept by /upgrade stop taking input
# ("You cannot write text in this buffer"). Scripts keep working across
# upgrades, so this one notices that rrc did not load, rebuilds it from the
# source checkout it was installed from, and loads it.
#
# `make install` installs and autoloads it. Turn it off with
#   /set plugins.var.python.rrc_autobuild.enabled off

import os

import weechat

SCRIPT_NAME = "rrc_autobuild"
SCRIPT_AUTHOR = "funkpower"
SCRIPT_VERSION = "1.0.0"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC = "Rebuild and load the rrc plugin when a WeeChat upgrade leaves it unloaded"

# filled in by `make install`
DEFAULT_SOURCE_DIR = "@SOURCE_DIR@"

OPTIONS = {
    "enabled": ("on", "rebuild and load rrc when it is not loaded at startup or after /upgrade"),
    "source_dir": ("", "weechat-rrc source checkout to rebuild from "
                   "(empty: the one `make install` ran from)"),
}

BUILD_TIMEOUT_MS = 5 * 60 * 1000

state = {"output": ""}


def say(text, error=False):
    prefix = weechat.prefix("error") if error else ""
    weechat.prnt("", "%s%s: %s" % (prefix, SCRIPT_NAME, text))


def rrc_loaded():
    infolist = weechat.infolist_get("plugin", "", "rrc")
    loaded = False
    if infolist:
        loaded = bool(weechat.infolist_next(infolist))
        weechat.infolist_free(infolist)
    return loaded


def plugin_dir():
    path = weechat.config_string(weechat.config_get("weechat.plugin.path"))
    return weechat.string_eval_path_home(path, {}, {}, {})


def check_cb(data, remaining_calls):
    if rrc_loaded() or weechat.config_get_plugin("enabled") != "on":
        return weechat.WEECHAT_RC_OK
    autoload = weechat.config_string(weechat.config_get("weechat.plugin.autoload"))
    if not weechat.string_match_list("rrc", autoload, 0):
        return weechat.WEECHAT_RC_OK
    pdir = plugin_dir()
    if not os.path.isfile(os.path.join(pdir, "rrc.so")):
        return weechat.WEECHAT_RC_OK
    src = weechat.config_get_plugin("source_dir")
    if not src and not DEFAULT_SOURCE_DIR.startswith("@"):
        src = DEFAULT_SOURCE_DIR
    if not src or not os.path.isfile(os.path.join(src, "Makefile")):
        say("rrc did not load, probably because it was built for an older WeeChat. "
            "Set plugins.var.python.rrc_autobuild.source_dir to your weechat-rrc "
            "checkout, or rebuild by hand: make && make install, then /plugin load rrc",
            error=True)
        return weechat.WEECHAT_RC_OK
    say("rrc did not load, probably because it was built for an older WeeChat; "
        "rebuilding it from %s" % src)
    state["output"] = ""
    weechat.hook_process_hashtable(
        "make",
        {"arg1": "-B", "arg2": "--no-print-directory", "arg3": "-C", "arg4": src,
         "arg5": "install", "arg6": "PLUGIN_DIR=" + pdir},
        BUILD_TIMEOUT_MS, "build_cb", "")
    return weechat.WEECHAT_RC_OK


def build_cb(data, command, return_code, out, err):
    state["output"] += out + err
    if return_code == weechat.WEECHAT_HOOK_PROCESS_RUNNING:
        return weechat.WEECHAT_RC_OK
    if return_code != 0:
        tail = state["output"].strip().splitlines()[-10:]
        say("the rebuild failed (exit %d). Last lines of the build:" % return_code, error=True)
        for line in tail:
            weechat.prnt("", "  " + line)
        return weechat.WEECHAT_RC_OK
    weechat.command("", "/plugin load rrc")
    if rrc_loaded():
        say("rrc rebuilt and loaded")
    else:
        say("rrc rebuilt but still did not load. If the error above says API "
            "mismatch, the installed WeeChat headers (weechat-dev / weechat-devel) "
            "are not the same version as the running WeeChat: update them, then "
            "/script reload %s" % SCRIPT_NAME, error=True)
    return weechat.WEECHAT_RC_OK


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", ""):
    for name, (default, desc) in OPTIONS.items():
        if not weechat.config_is_set_plugin(name):
            weechat.config_set_plugin(name, default)
        weechat.config_set_desc_plugin(name, desc)
    # plugins autoload around the scripts: look once they all have
    weechat.hook_timer(1000, 0, 1, "check_cb", "")
